import { NextResponse, type NextRequest } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';
import * as admin from 'firebase-admin';

export async function POST(request: NextRequest) {
  try {
    // Get the authorization token
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await adminAuth.verifyIdToken(token);
    const callingUid = decodedToken.uid;

    // Verify admin role
    const callerDoc = await adminDb.collection('users').doc(callingUid).get();
    if (!callerDoc.exists || callerDoc.data()?.role !== 'admin') {
      return NextResponse.json({ error: 'Permission denied. Admin role required.' }, { status: 403 });
    }

    // Get the data from request body
    const body = await request.json();
    const { email, password, displayName, role } = body;

    if (!email || !password || !displayName || !role) {
      return NextResponse.json({ error: 'Missing required fields.' }, { status: 400 });
    }

    // Create user in Firebase Auth
    const userRecord = await adminAuth.createUser({ email, password, displayName });

    // Set custom claims
    await adminAuth.setCustomUserClaims(userRecord.uid, { role });

    // Create user document in Firestore
    const userDoc = {
      uid: userRecord.uid,
      email,
      displayName,
      role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      profilePicUrl: '/images/rr.png',
    };

    await adminDb.collection('users').doc(userRecord.uid).set(userDoc);

    return NextResponse.json({
      data: {
        message: `User ${displayName} created successfully!`,
        newUser: { ...userDoc, id: userRecord.uid }
      }
    }, { status: 200 });
  } catch (error: any) {
    console.error('Error adding user:', error);
    return NextResponse.json({
      error: {
        code: error.code || 'internal',
        message: error.message || 'An unexpected error occurred.'
      }
    }, { status: 500 });
  }
}
