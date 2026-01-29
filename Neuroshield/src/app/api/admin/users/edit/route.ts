import { NextResponse, type NextRequest } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

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
    const { uid, displayName, role } = body;

    if (!uid || !displayName || !role) {
      return NextResponse.json({ error: 'Missing required fields.' }, { status: 400 });
    }

    // Update user in Firebase Auth
    await adminAuth.updateUser(uid, { displayName });

    // Set custom claims
    await adminAuth.setCustomUserClaims(uid, { role });

    // Update user document in Firestore
    await adminDb.collection('users').doc(uid).update({ displayName, role });

    return NextResponse.json({
      data: { message: 'User updated successfully!' }
    }, { status: 200 });
  } catch (error: any) {
    console.error('Error editing user:', error);
    return NextResponse.json({
      error: {
        code: error.code || 'internal',
        message: error.message || 'An unexpected error occurred.'
      }
    }, { status: 500 });
  }
}
