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

    // Get the uid from request body
    const body = await request.json();
    const { uid } = body;

    if (!uid) {
      return NextResponse.json({ error: 'Missing required field: uid' }, { status: 400 });
    }

    // Delete user from Firebase Auth
    await adminAuth.deleteUser(uid);

    // Delete user document from Firestore
    await adminDb.collection('users').doc(uid).delete().catch((error) => {
      if (error.code !== 'not-found') {
        console.warn(`Auth user ${uid} deleted, but Firestore doc failed:`, error.message);
      }
    });

    return NextResponse.json({ data: { message: 'User deleted successfully.' } }, { status: 200 });
  } catch (error: any) {
    console.error('Error deleting user:', error);
    return NextResponse.json({
      error: {
        code: error.code || 'internal',
        message: error.message || 'An unexpected error occurred.'
      }
    }, { status: 500 });
  }
}
