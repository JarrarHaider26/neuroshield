
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

admin.initializeApp();

const db = admin.firestore();

// Helper function to verify if the caller is an admin by checking Firestore
const verifyAdmin = async (context: functions.https.CallableContext) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "The function must be called while authenticated."
    );
  }

  try {
    const userDocRef = db.collection("users").doc(context.auth.uid);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists() || userDoc.data()?.role !== "admin") {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You must have an 'admin' role in the database to perform this action."
      );
    }
  } catch (error) {
    // If it's already an HttpsError, rethrow it.
    if (error instanceof functions.https.HttpsError) {
      throw error;
    }
    // Log the underlying error for debugging.
    console.error("Error verifying admin status:", error);
    // Throw a generic internal error to the client.
    throw new functions.https.HttpsError("internal", "An internal error occurred while verifying admin status.");
  }
};


export const addUser = functions.https.onCall(async (data, context) => {
  await verifyAdmin(context);

  const { email, password, displayName, role } = data;

  if (!email || !password || !displayName || !role) {
      throw new functions.https.HttpsError(
          "invalid-argument",
          "Missing required fields: email, password, displayName, role."
      );
  }

  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName,
    });

    await admin.auth().setCustomUserClaims(userRecord.uid, { role });

    const userDoc = {
      uid: userRecord.uid,
      email,
      displayName,
      role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      profilePicUrl: "/images/rr.png", // Default static image
    };

    await db.collection("users").doc(userRecord.uid).set(userDoc);

    return {
      message: `User ${displayName} created successfully!`,
      newUser: { ...userDoc, id: userRecord.uid },
    };
  } catch (error: any) {
    console.error("Error creating user:", error.code, error.message);
    // Convert Firebase Auth errors to client-friendly HttpsError
    const clientMessage = error.message || `An unexpected error occurred while creating the user.`;
    throw new functions.https.HttpsError("internal", clientMessage, { code: error.code });
  }
});

export const editUser = functions.https.onCall(async (data, context) => {
  await verifyAdmin(context);

  const { uid, displayName, role } = data;

   if (!uid || !displayName || !role) {
      throw new functions.https.HttpsError(
          "invalid-argument",
          "Missing required fields: uid, displayName, role."
      );
  }

  try {
    await admin.auth().updateUser(uid, { displayName });
    await admin.auth().setCustomUserClaims(uid, { role });
    await db.collection("users").doc(uid).update({ displayName, role });

    return { message: "User updated successfully!" };
  } catch (error: any) {
    console.error("Error editing user:", error.code, error.message);
    const clientMessage = error.message || `An unexpected error occurred while editing the user.`;
    throw new functions.https.HttpsError("internal", clientMessage, { code: error.code });
  }
});

export const deleteUser = functions.https.onCall(async (data, context) => {
  await verifyAdmin(context);

  const { uid } = data;

  if (!uid) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Missing required field: uid."
    );
  }

  try {
    // This is the most critical step. If this fails, the function should stop.
    await admin.auth().deleteUser(uid);
    
    // This step is secondary. We attempt to delete the Firestore document,
    // but we don't fail the entire function if it doesn't exist.
    const userDocRef = db.collection("users").doc(uid);
    await userDocRef.delete().catch((firestoreError) => {
      // We only log an error if it's something other than "document not found".
      if (firestoreError.code !== 'not-found') {
        console.warn(`Auth user ${uid} was deleted, but their Firestore document could not be. Error:`, firestoreError.message);
      }
    });

    return { message: "User deleted successfully." };

  } catch (error: any) {
    console.error("Error deleting user from Firebase Auth:", error.code, error.message);
    
    // Provide a more specific and helpful error message back to the client.
    let clientMessage = `An unexpected error occurred: ${error.message}`;
    if (error.code === 'auth/user-not-found') {
        clientMessage = "The user could not be found in Firebase Authentication. They may have already been deleted.";
    }
    
    // This throws a clear error that the client UI can catch and display.
    throw new functions.https.HttpsError("internal", clientMessage, {code: error.code});
  }
});


export const grantAdminRole = functions.https.onCall(async (data, context) => {
    // This is an administrative function. Ensure the caller is an admin.
    await verifyAdmin(context);

    const { email } = data;
    if (!email) {
        throw new functions.https.HttpsError('invalid-argument', 'Email address is required.');
    }

    try {
        const user = await admin.auth().getUserByEmail(email);
        await admin.auth().setCustomUserClaims(user.uid, { role: 'admin' });
        await db.collection('users').doc(user.uid).update({ role: 'admin' });

        return { message: `Success! ${email} has been made an admin.` };
    } catch (error: any) {
        console.error('Error granting admin role:', error);
        throw new functions.https.HttpsError('internal', error.message);
    }
});
