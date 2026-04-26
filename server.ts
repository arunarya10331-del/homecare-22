import express, { Request, Response, NextFunction } from 'express';
// Remove static import of vite
// import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';
import crypto from 'crypto';
import dotenv from 'dotenv';
import admin from 'firebase-admin';

dotenv.config();

// Extend Express Request type
interface AuthRequest extends Request {
  user?: admin.auth.DecodedIdToken;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize Firebase Admin
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
    });
  } catch (error) {
    console.error('Firebase Admin initialization failed:', error);
  }
}

const db = admin.firestore();

export const app = express();
const PORT = 3000;

app.use(express.json());

// Auth Middleware
const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

const isAdminMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  
  const userDoc = await db.collection('users').doc(req.user.uid).get();
  const userData = userDoc.data();
  
  if (userData?.role === 'admin' || req.user.email === 'arunarya10331@gmail.com') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden: Admin access required' });
  }
};

// Cashfree Config
const CF_APP_ID = process.env.CASHFREE_APP_ID;
const CF_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CF_ENV = process.env.CASHFREE_ENV || 'sandbox';
const CF_BASE_URL = CF_ENV === 'production' 
  ? 'https://api.cashfree.com/pg' 
  : 'https://sandbox.cashfree.com/pg';

const cfHeaders = {
  'x-client-id': CF_APP_ID || '',
  'x-client-secret': CF_SECRET_KEY || '',
  'x-api-version': '2023-08-01',
  'Content-Type': 'application/json'
};

// API Routes
app.post('/api/payments/create-order', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { amount, customerId, customerPhone, customerEmail, bookingId, serviceType } = req.body;

    // Ensure user is creating order for themselves
    if (req.user?.uid !== customerId) {
      return res.status(403).json({ error: 'Forbidden: Cannot create order for another user' });
    }

    if (!CF_APP_ID || !CF_SECRET_KEY) {
      return res.status(500).json({ error: 'Cashfree credentials not configured' });
    }

    const orderId = `order_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    const orderData = {
      order_id: orderId,
      order_amount: amount,
      order_currency: 'INR',
      customer_details: {
        customer_id: customerId,
        customer_phone: customerPhone,
        customer_email: customerEmail
      },
      order_meta: {
        return_url: `${req.headers.origin}/payment-status?order_id={order_id}`,
        notify_url: `${req.headers.origin}/api/payments/webhook`,
        payment_methods: 'cc,dc,ccc,ppc,nb,upi,app'
      },
      order_note: `Payment for ${serviceType}`,
      order_tags: {
        booking_id: bookingId,
        user_id: customerId,
        service_type: serviceType
      }
    };

    const response = await axios.post(`${CF_BASE_URL}/orders`, orderData, { headers: cfHeaders });
    
    // Store pending transaction in Firestore
    await db.collection('cashfree_transactions').doc(orderId).set({
      id: orderId,
      orderId,
      cfOrderId: response.data.cf_order_id,
      userId: customerId,
      bookingId: bookingId || null,
      amount,
      currency: 'INR',
      status: 'PENDING',
      createdAt: new Date().toISOString()
    });

    res.json(response.data);
  } catch (error: any) {
    console.error('Cashfree Order Creation Error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to create payment order' });
  }
});

app.post('/api/payments/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-webhook-signature'] as string;
    const timestamp = req.headers['x-webhook-timestamp'] as string;
    
    // Webhook verification
    const webhookSecret = process.env.CASHFREE_WEBHOOK_SECRET;
    if (webhookSecret) {
      const rawBody = JSON.stringify(req.body);
      const signatureData = timestamp + rawBody;
      const expectedSignature = crypto
        .createHmac('sha256', webhookSecret)
        .update(signatureData)
        .digest('base64');
        
      if (signature !== expectedSignature) {
        console.error('Invalid Webhook Signature');
        return res.status(401).send('Invalid signature');
      }
    }

    const { data } = req.body;
    if (!data) return res.status(400).send('No data');

    const { order, payment } = data;
    if (!order || !payment) return res.status(400).send('Invalid webhook data');

    const orderId = order.order_id;
    const status = payment.payment_status; // SUCCESS, FAILED, PENDING

    const transactionRef = db.collection('cashfree_transactions').doc(orderId);
    await transactionRef.update({
      status: status,
      paymentMode: payment.payment_group,
      paymentTime: payment.payment_time,
      cfPaymentId: payment.cf_payment_id
    });

    // Update booking status if applicable
    const txDoc = await transactionRef.get();
    const txData = txDoc.data();
    if (txData?.bookingId && status === 'SUCCESS') {
      await db.collection('bookings').doc(txData.bookingId).update({
        paymentStatus: 'paid',
        paymentMethod: 'online'
      });

      // Create notification
      await db.collection('notifications').add({
        userId: txData.userId,
        title: 'Payment Successful',
        message: `Your payment of ₹${txData.amount} for ${txData.orderId} was successful.`,
        type: 'payment',
        read: false,
        createdAt: new Date().toISOString()
      });
    }

    res.status(200).send('Webhook processed');
  } catch (error) {
    console.error('Webhook Error:', error);
    res.status(500).send('Webhook failed');
  }
});

app.post('/api/payments/refund', authenticate, isAdminMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { orderId, amount, reason } = req.body;

    const refundData = {
      refund_amount: amount,
      refund_id: `ref_${Date.now()}`,
      refund_note: reason
    };

    const response = await axios.post(`${CF_BASE_URL}/orders/${orderId}/refunds`, refundData, { headers: cfHeaders });
    
    // Store refund record
    await db.collection('refund_records').doc(response.data.refund_id).set({
      id: response.data.refund_id,
      transactionId: orderId,
      orderId,
      refundId: response.data.refund_id,
      amount,
      reason,
      status: 'INITIATED',
      createdAt: new Date().toISOString()
    });

    // Update transaction status
    await db.collection('cashfree_transactions').doc(orderId).update({
      status: 'REFUNDED'
    });

    res.json(response.data);
  } catch (error: any) {
    console.error('Refund Error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to initiate refund' });
  }
});

app.get('/api/payments/status/:orderId', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { orderId } = req.params;
    
    // Check if transaction belongs to user
    const txDoc = await db.collection('cashfree_transactions').doc(orderId).get();
    if (txDoc.exists && txDoc.data()?.userId !== req.user?.uid && req.user?.email !== 'arunarya10331@gmail.com') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const response = await axios.get(`${CF_BASE_URL}/orders/${orderId}`, { headers: cfHeaders });
    res.json(response.data);
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch order status' });
  }
});

// Manual Override
app.post('/api/payments/manual-override', authenticate, isAdminMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { bookingId, amount, note } = req.body;
    
    await db.collection('bookings').doc(bookingId).update({
      paymentStatus: 'paid',
      paymentMethod: 'cash',
      paymentNote: note
    });

    await db.collection('cashfree_transactions').add({
      userId: 'manual',
      bookingId,
      amount,
      status: 'SUCCESS',
      paymentMode: 'CASH',
      note,
      createdAt: new Date().toISOString()
    });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Manual override failed' });
  }
});

// Booking Cancellation
app.post('/api/bookings/cancel', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { bookingId, reason } = req.body;
    
    const bookingRef = db.collection('bookings').doc(bookingId);
    const bookingDoc = await bookingRef.get();
    
    if (!bookingDoc.exists) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    const bookingData = bookingDoc.data();

    // Ensure user owns the booking or is admin
    if (bookingData?.userId !== req.user?.uid && req.user?.email !== 'arunarya10331@gmail.com') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await bookingRef.update({
      status: 'cancelled',
      cancellationReason: reason,
      cancelledAt: new Date().toISOString()
    });
    
    let refundInitiated = false;

    // Check if refund is needed
    if (bookingData?.paymentStatus === 'paid' && bookingData?.paymentMethod === 'online') {
      // Find the transaction
      const txSnapshot = await db.collection('cashfree_transactions')
        .where('bookingId', '==', bookingId)
        .where('status', '==', 'SUCCESS')
        .limit(1)
        .get();
        
      if (!txSnapshot.empty) {
        const txData = txSnapshot.docs[0].data();
        // Initiate refund via Cashfree
        const refundData = {
          refund_amount: txData.amount,
          refund_id: `ref_cancel_${Date.now()}`,
          refund_note: `Cancellation: ${reason}`
        };
        
        try {
          const refundResponse = await axios.post(`${CF_BASE_URL}/orders/${txData.orderId}/refunds`, refundData, { headers: cfHeaders });
          
          await db.collection('refund_records').doc(refundResponse.data.refund_id).set({
            id: refundResponse.data.refund_id,
            transactionId: txData.orderId,
            orderId: txData.orderId,
            refundId: refundResponse.data.refund_id,
            amount: txData.amount,
            reason: reason,
            status: 'INITIATED',
            createdAt: new Date().toISOString()
          });
          
          await db.collection('cashfree_transactions').doc(txData.orderId).update({
            status: 'REFUNDED'
          });
          refundInitiated = true;
        } catch (refundError: any) {
          console.error('Auto-refund failed during cancellation:', refundError.response?.data || refundError.message);
        }
      }
    }
    
    res.json({ success: true, refundInitiated });
  } catch (error) {
    console.error('Booking Cancellation Error:', error);
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

// Secure Contact Sharing Endpoint
app.get('/api/bookings/contact/:bookingId', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { bookingId } = req.params;
    const requesterUid = req.user?.uid;

    if (!requesterUid) return res.status(401).json({ error: 'Unauthorized' });

    // 1. Fetch Booking
    const bookingDoc = await db.collection('bookings').doc(bookingId).get();
    if (!bookingDoc.exists) return res.status(404).json({ error: 'Booking not found' });
    const booking = bookingDoc.data();

    // 2. Validate Membership or Admin
    const isClient = booking?.userId === requesterUid;
    const isWorker = booking?.workerId === requesterUid;
    
    // Check if requester is admin
    const adminDoc = await db.collection('admins').doc(requesterUid).get();
    const isAdmin = adminDoc.exists;

    if (!isClient && !isWorker && !isAdmin) return res.status(403).json({ error: 'Access denied' });

    // 3. Validate Status (Admins can see always, others only confirmed/completed)
    if (!isAdmin && booking?.status !== 'confirmed' && booking?.status !== 'completed') {
      return res.status(403).json({ error: 'Contact details only available for confirmed bookings' });
    }

    // 4. Check Global Settings (Admins ignore this)
    if (!isAdmin) {
      const globalSettingsDoc = await db.collection('settings').doc('global').get();
      const enableContactSharing = globalSettingsDoc.data()?.enableContactSharing ?? true;
      if (!enableContactSharing) {
        return res.status(403).json({ error: 'Contact sharing is currently disabled by administrator' });
      }
    }

    // 5. Check Subscription (Admins ignore this)
    if (!isAdmin) {
      const userDoc = await db.collection('users').doc(requesterUid).get();
      const userData = userDoc.data();
      
      let hasActiveSubscription = userData?.isFreeUser || userData?.subscriptionType === 'special';
      
      // If it's a worker, check their worker-specific subscription status
      if (userData?.role === 'worker') {
        const workerDoc = await db.collection('workers').doc(requesterUid).get();
        if (workerDoc.data()?.subscriptionStatus === 'paid') {
          hasActiveSubscription = true;
        }
      } else {
        hasActiveSubscription = true; // Temporary: simplify for client access
      }
      
      if (!hasActiveSubscription) {
        return res.status(403).json({ 
          error: 'Subscription required to view contact details', 
          code: 'SUBSCRIPTION_REQUIRED' 
        });
      }
    }

    // 6. Fetch Target Profile
    const targetUid = isClient ? booking?.workerId : booking?.userId;
    const targetUserDoc = await db.collection('users').doc(targetUid).get();
    const targetData = targetUserDoc.data();

    res.json({
      name: targetData?.name,
      phone: targetData?.phone,
      email: targetData?.email,
      address: targetData?.address,
      photoURL: targetData?.photoURL
    });
  } catch (error) {
    console.error('Contact Fetch Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vite middleware
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production' || process.env.VERCEL === '1';
  
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT} [${isProd ? 'PRODUCTION' : 'DEVELOPMENT'}]`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
