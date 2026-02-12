require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const { getAuth } = require("firebase-admin/auth");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);
app.use(express.json());

app.use((req, res, next) => {
  console.log("Incoming:", req.method, req.url);
  next();
});

const uri = `mongodb+srv://${process.env.MONGOUSER}:${process.env.MONGOPASS}@programmingheroassignme.7jfqtzz.mongodb.net/?appName=ProgrammingHeroAssignment`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const admin = require("firebase-admin");

const multer = require("multer");

const decoded = Buffer.from(process.env.FIREBASE_SECRET, "base64").toString(
  "utf8",
);

var serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const auth = getAuth();

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const photoStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "profile_photo",
    allowed_formats: [
      "jpg",
      "jpeg",
      "png",
      "gif",
      "webp",
      "avif",
      "svg",
      "heic",
    ],
    transformation: [
      { fetch_format: "auto" },
      { quality: "auto" },
      { crop: "fill", gravity: "auto" },
    ],
  },
});

const uploadProfile = multer({ storage: photoStorage });
const cookieOption = {
  httpOnly: true,
  secure: false,
  sameSite: "lax",
  maxAge: 2592000,
};

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    const finTrackDB = client.db("FinTrackDB");
    const userCollection = finTrackDB.collection("user");

    app.post(
      "/register",
      uploadProfile.single("profile_photo"),
      async (req, res) => {
        try {
          const user = req.body;
          if (!user) {
            return res.status(400).json({ message: "User Info Doesn't Exist" });
          }
          if (!user.name) {
            return res.status(400).json({ message: "Name required" });
          }
          if (!user.password) {
            return res.status(400).json({ message: "Password required" });
          }
          if (!user.email) {
            return res.status(400).json({ message: "Email required" });
          }
          if (!req.file) {
            return res.status(400).json({ message: "Photo required" });
          }
          const plainPass = user.password;
          const hashPassword = await bcrypt.hash(
            user.password,
            parseInt(process.env.SALT_ROUND),
          );
          user.password = hashPassword;
          user.role = process.env.USER_ROLE || "user";
          user.createdAt = new Date();
          user.photo = req.file?.path;
          console.log(user);
          const query = { email: user.email };
          const existingUser = await userCollection.findOne(query);

          if (existingUser) {
            return res.status(409).json({ message: "User already exists" });
          } else {
            auth
              .createUser({
                email: user.email,
                password: plainPass,
                displayName: user.name,
                photoURL: user.photo,
              })
              .then(async (userRecord) => {
                user.firebaseUID = userRecord.uid;
                const result = await userCollection.insertOne(user);
                console.log("Successfully created new user:", userRecord.uid);
                await auth.setCustomUserClaims(userRecord.uid, {
                  role: process.env.USER_ROLE,
                });
                const firebaseToken = await auth.createCustomToken(
                  userRecord.uid,
                );
                res.cookie("firebaseToken", firebaseToken, cookieOption);
                res.status(201).json({
                  message: "Registration successful",
                  firebaseToken,
                  user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    photo: user.photo,
                    role: user.role,
                  },
                });
              })
              .catch((error) => {
                console.log("Error creating new user:", error);
                res.status(500).json({ message: "Failed to save user" });
              });
          }
        } catch (err) {
          console.log(err);
          res.status(500).json({ message: "Internal Server Error" });
        }
      },
    );
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
