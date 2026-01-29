import { NextRequest, NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await adminAuth.verifyIdToken(token);
    const callingUid = decodedToken.uid;

    // Verify admin role
    const callerDoc = await adminDb.collection('users').doc(callingUid).get();
    if (!callerDoc.exists || callerDoc.data()?.role !== 'admin') {
      return NextResponse.json({ error: 'Admin access required' }, { status: 403 });
    }

    // Get all users from Firestore
    const usersSnapshot = await adminDb.collection('users').get();
    
    let updated = 0;
    let sessionsRevoked = 0;
    const batch = adminDb.batch();

    // Set all users to emailVerified: false and revoke their sessions
    for (const doc of usersSnapshot.docs) {
      // Update Firestore
      batch.update(doc.ref, { emailVerified: false });
      updated++;
      
      // Revoke refresh tokens to force re-authentication
      // This will log out all currently logged-in users
      try {
        await adminAuth.revokeRefreshTokens(doc.id);
        sessionsRevoked++;
      } catch (error) {
        console.error(`Error revoking tokens for user ${doc.id}:`, error);
      }
    }

    await batch.commit();

    return NextResponse.json({
      success: true,
      message: `All users set to unverified and logged out. ${updated} users updated, ${sessionsRevoked} sessions revoked.`,
      data: { updated, sessionsRevoked }
    });

  } catch (error: any) {
    console.error('Migration error:', error);
    return NextResponse.json({ 
      error: 'Migration failed', 
      details: error.message 
    }, { status: 500 });
  }
}
