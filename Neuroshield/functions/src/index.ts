
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as cors from "cors";

admin.initializeApp();
const db = admin.firestore();
const corsHandler = cors({ origin: true, credentials: true });

// Helper to get UID from request, crucial for onRequest functions
const getUidFromRequest = async (req: functions.https.Request): Promise<string> => {
    if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        throw new functions.https.HttpsError("unauthenticated", "No bearer token provided.");
    }
    const idToken = req.headers.authorization.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        return decodedToken.uid;
    } catch (error) {
        console.error("Error verifying ID token:", error);
        throw new functions.https.HttpsError("unauthenticated", "Invalid or expired token.");
    }
};

// Helper function to verify if the caller is an admin.
const verifyAdmin = async (uid: string) => {
  try {
    const userDocRef = db.collection("users").doc(uid);
    const userDoc = await userDocRef.get();
    if (!userDoc.exists() || userDoc.data()?.role !== "admin") {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You must have an 'admin' role to perform this action."
      );
    }
  } catch (error) {
    if (error instanceof functions.https.HttpsError) throw error;
    console.error("Error verifying admin status:", error);
    throw new functions.https.HttpsError("internal", "An internal error occurred while verifying admin status.");
  }
};


export const addUser = functions.https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            res.status(405).send('Method Not Allowed');
            return;
        }
        try {
            const callingUid = await getUidFromRequest(req);
            await verifyAdmin(callingUid);

            // onRequest functions expect data in req.body.data
            const { email, password, displayName, role } = req.body.data;
            if (!email || !password || !displayName || !role) {
                throw new functions.https.HttpsError("invalid-argument", "Missing required fields.");
            }

            const userRecord = await admin.auth().createUser({ email, password, displayName });
            await admin.auth().setCustomUserClaims(userRecord.uid, { role });
            const userDoc = {
                uid: userRecord.uid, email, displayName, role,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                profilePicUrl: "/images/rr.png",
            };
            await db.collection("users").doc(userRecord.uid).set(userDoc);
            res.status(200).send({ data: { message: `User ${displayName} created successfully!`, newUser: { ...userDoc, id: userRecord.uid } } });
        } catch (error: any) {
            console.error("Error adding user:", error);
            const code = error.code || "internal";
            const message = error.message || "An unexpected error occurred.";
            res.status(500).send({ error: { code, message } });
        }
    });
});

export const editUser = functions.https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            res.status(405).send('Method Not Allowed');
            return;
        }
        try {
            const callingUid = await getUidFromRequest(req);
            await verifyAdmin(callingUid);

            const { uid, displayName, role } = req.body.data;
             if (!uid || !displayName || !role) {
                throw new functions.https.HttpsError("invalid-argument", "Missing required fields.");
            }

            await admin.auth().updateUser(uid, { displayName });
            await admin.auth().setCustomUserClaims(uid, { role });
            await db.collection("users").doc(uid).update({ displayName, role });

            res.status(200).send({ data: { message: "User updated successfully!" } });
        } catch (error: any) {
            console.error("Error editing user:", error);
            const code = error.code || "internal";
            const message = error.message || "An unexpected error occurred.";
            res.status(500).send({ error: { code, message } });
        }
    });
});


export const deleteUser = functions.https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            res.status(405).send('Method Not Allowed');
            return;
        }
        try {
            const callingUid = await getUidFromRequest(req);
            await verifyAdmin(callingUid);

            const { uid } = req.body.data;
            if (!uid) {
                throw new functions.https.HttpsError("invalid-argument", "Missing required field: uid.");
            }

            await admin.auth().deleteUser(uid);
            const userDocRef = db.collection("users").doc(uid);
            await userDocRef.delete().catch((firestoreError) => {
                if (firestoreError.code !== 'not-found') {
                    console.warn(`Auth user ${uid} deleted, but Firestore doc failed:`, firestoreError.message);
                }
            });
            res.status(200).send({ data: { message: "User deleted successfully." } });
        } catch (error: any) {
            console.error("Error deleting user:", error);
            const code = error.code || "internal";
            const message = error.message || "An unexpected error occurred.";
            res.status(500).send({ error: { code, message } });
        }
    });
});


export const grantAdminRole = functions.https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
         if (req.method !== 'POST') {
            res.status(405).send('Method Not Allowed');
            return;
        }
        try {
            const callingUid = await getUidFromRequest(req);
            await verifyAdmin(callingUid);

            const { email } = req.body.data;
            if (!email) {
                throw new functions.https.HttpsError('invalid-argument', 'Email address is required.');
            }

            const user = await admin.auth().getUserByEmail(email);
            await admin.auth().setCustomUserClaims(user.uid, { role: 'admin' });
            await db.collection('users').doc(user.uid).update({ role: 'admin' });

            res.status(200).send({ data: { message: `Success! ${email} has been made an admin.` } });
        } catch (error: any) {
            console.error('Error granting admin role:', error);
            const code = error.code || "internal";
            const message = error.message || "An unexpected error occurred.";
            res.status(500).send({ error: { code, message } });
        }
    });
});
