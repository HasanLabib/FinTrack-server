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
    origin: "https://fin-track-client-xi.vercel.app",
    credentials: true,
  }),
);
app.use(express.json());

app.use((req, res, next) => {
  //console.log("Incoming:", req.method, req.url);
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
const upload = multer();
const cookieOption = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 2592000,
};

const verifyFBToken = async (req, res, next) => {
  const idToken = req.headers.authorization;
  if (!idToken?.startsWith("Bearer ")) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  try {
    //console.log(idToken.split(" "));
    const token = idToken.split(" ")[1];
    const decoded = await auth.verifyIdToken(token);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

app.get("/", (req, res) => {
  res.send("Fintrack server is running");
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    const finTrackDB = client.db("FinTrackDB");
    const userCollection = finTrackDB.collection("user");
    const categoryCollection = finTrackDB.collection("category");
    const incomeCollection = finTrackDB.collection("incomeCollection");
    const transactionCollection = finTrackDB.collection(
      "transactionCollection",
    );
    const savingCollection = finTrackDB.collection("savingCollection");
    const expenseCollection = finTrackDB.collection("expenseCollection");
    const tipsCollection = finTrackDB.collection("tipsCollection");
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.decoded_email;
        const query = { email };
        const findUser = await userCollection.findOne(query);
        if (findUser.role !== "admin") {
          return res.status(403).send({ message: "Admin only" });
        }
        next();
      } catch (err) {
        console.log(err);
      }
    };
    app.post(
      "/register",
      uploadProfile.single("profile_photo"),
      async (req, res) => {
        try {
          const user = req.body;
          //console.log(user);
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
          //console.log(user);
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
                //console.log("Successfully created new user:", userRecord.uid);
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
                switch (error.code) {
                  case "auth/email-already-in-use":
                    res.status(500).json({
                      message: "User already exists in the database.",
                    });
                    break;
                  case "auth/weak-password":
                    res.status(500).json({
                      message: "At least 6 ta digit password required",
                    });
                    break;
                  case "auth/invalid-email":
                    res.status(500).json({
                      message: "Invalid email format. Please check your email.",
                    });
                    break;
                  default:
                    res.status(500).json({ message: "Failed to save user" });
                }
              });
          }
        } catch (err) {
          console.log(err);
          res.status(500).json({ message: "Internal Server Error" });
        }
      },
    );
    app.post("/login", async (req, res) => {
      try {
        const user = req.body;
        if (!user) {
          return res.status(400).json({ message: "User Info Doesn't Exist" });
        }
        if (!user.password) {
          return res.status(400).json({ message: "Password required" });
        }
        if (!user.email) {
          return res.status(400).json({ message: "Email required" });
        }

        const query = { email: user.email };
        const existingUser = await userCollection.findOne(query);
        if (!existingUser) {
          return res.status(404).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(
          user.password,
          existingUser.password,
        );
        if (!isMatch) {
          return res.status(401).json({ message: "Incorrect password" });
        }

        if (existingUser) {
          auth
            .getUser(existingUser.firebaseUID)
            .then(async (userRecord) => {
              const firebaseToken = await auth.createCustomToken(
                userRecord.uid,
              );
              res.cookie("firebaseToken", firebaseToken, cookieOption);
              res.status(200).json({
                message: "Login successful",
                firebaseToken,
                user: {
                  id: existingUser._id,
                  name: existingUser.name,
                  email: existingUser.email,
                  photo: existingUser.photo,
                  role: existingUser.role,
                },
              });
              console.log(
                `Successfully fetched user data: ${userRecord.toJSON()}`,
              );
            })
            .catch((error) => {
              console.log("Error fetching user data:", error);
              res.status(500).json({ message: "Internal Server Error" });
            });
        }
      } catch (err) {
        //console.log(err);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
    app.post("/logout", (req, res) => {
      res.clearCookie("firebaseToken", { path: "/" });
      res.status(200).json({ message: "Logged out successfully" });
    });

    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;

      const user = await userCollection.findOne({ email });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.status(200).json(user);
    });

    //--------Admin Dashboard Api Start------------

    app.get("/admin/users", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        res.send(users);
      } catch (err) {
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    app.patch(
      "/admin/make-admin/:email",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;

        const result = await userCollection.updateOne(
          { email },
          { $set: { role: "admin", status: "approved" } },
        );

        res.send(result);
      },
    );

    app.patch(
      "/admin/make-normal/:email",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;

        const result = await userCollection.updateOne(
          { email },
          { $set: { role: "user", status: "approved" } },
        );

        res.send(result);
      },
    );

    app.post("/category", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const category = {
          ...req.body,
          createdByEmail: req.decoded_email,
          createdAt: new Date(),
        };
        const result = await categoryCollection.insertOne(category);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to create category" });
      }
    });

    app.put(
      "/update-category/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const updateCategory = req.body;
          delete updateCategory.createdByEmail;

          const query = { _id: new ObjectId(id) };

          const result = await categoryCollection.updateOne(query, {
            $set: updateCategory,
          });
          res.status(200).json(result);
        } catch (err) {
          console.error(err);
          res.status(500).send({ error: "Failed to update category" });
        }
      },
    );
    app.get("/category", verifyFBToken, verifyAdmin, async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = 8;
      const skip = (page - 1) * limit;
      const category = await categoryCollection
        .find({})
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray();
      const totalCategory = await categoryCollection.countDocuments({});
      res.send({
        category,
        totalCategory,
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCategory / limit),
      });
    });

    app.delete(
      "/delete-category/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        try {
          const result = await categoryCollection.deleteOne(query);
          res.status(200).json(result);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: "Failed to delete category" });
        }
      },
    );

    app.get("/all-transaction", verifyFBToken, async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = 8;
      const skip = (page - 1) * limit;

      const {
        search = "",
        category = "",
        type = "",
        sortField = "createdAt",
        sortOrder = "desc",
      } = req.query;

      const filter = {};

      if (search) {
        filter.$or = [
          { source: { $regex: search, $options: "i" } },
          { note: { $regex: search, $options: "i" } },
          { createdByEmail: { $regex: search, $options: "i" } },
          { category: { $regex: search, $options: "i" } },
        ];
      }

      if (category) filter.category = category;
      if (type) filter.type = type;

      const sort = {};
      sort[sortField] = sortOrder === "asc" ? 1 : -1;

      try {
        const transactions = await transactionCollection
          .find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalTran = await transactionCollection.countDocuments(filter);

        res.status(200).send({
          transactions, // consistent key name with user endpoint
          totalTran,
          currentPage: page,
          totalPages: Math.ceil(totalTran / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch transaction entries" });
      }
    });

    const MONTH_NAMES = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec",
    ];

    const CHART_COLOR_PALETTE = [
      "#FF6384",
      "#36A2EB",
      "#FFCE56",
      "#8BC34A",
      "#FF9800",
      "#9C27B0",
      "#4BC0C0",
      "#9966FF",
    ];

    app.get(
      "/admin/analytics",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const selectedYear =
          parseInt(req.query.year) || new Date().getFullYear();
        try {
          
          const yearlyIncomes = await incomeCollection
            .find({
              date: {
                $gte: new Date(`${selectedYear}-01-01`),
                $lte: new Date(`${selectedYear}-12-31`),
              },
            })
            .toArray();
          const yearlyExpenses = await expenseCollection
            .find({
              date: {
                $gte: new Date(`${selectedYear}-01-01`),
                $lte: new Date(`${selectedYear}-12-31`),
              },
            })
            .toArray();
          const yearlySavings = await savingCollection
            .find({
              date: {
                $gte: new Date(`${selectedYear}-01-01`),
                $lte: new Date(`${selectedYear}-12-31`),
              },
            })
            .toArray();

          
          const yearlyTransactions = [
            ...yearlyIncomes.map((item) => ({
              ...item,
              type: item.type || "Income",
            })),
            ...yearlyExpenses.map((item) => ({
              ...item,
              type: item.type || "Expense",
            })),
            ...yearlySavings.map((item) => ({
              ...item,
              type: item.type || "Savings",
            })),
          ];

          const monthlyIncome = Array(12).fill(0);
          const monthlyExpense = Array(12).fill(0);
          const monthlySavings = Array(12).fill(0);
          const categoryTotals = {};
          yearlyTransactions.forEach((transaction) => {
            const monthIndex = new Date(transaction.date).getMonth();
            if (transaction.type === "Income") {
              monthlyIncome[monthIndex] += parseFloat(transaction.amount || 0);
            }
            if (transaction.type === "Expense") {
              monthlyExpense[monthIndex] += parseFloat(transaction.amount || 0);
              const category = transaction.category || "Uncategorized";
              categoryTotals[category] =
                (categoryTotals[category] || 0) +
                parseFloat(transaction.amount || 0);
            }
            if (transaction.type === "Savings") {
              monthlySavings[monthIndex] += parseFloat(transaction.amount || 0);
            }
          });

          const monthlyBalanceTrend = Array(12).fill(0);
          let runningBalance = 0;
          for (let monthIndex = 0; monthIndex < 12; monthIndex++) {
            runningBalance +=
              monthlyIncome[monthIndex] - monthlyExpense[monthIndex];
            monthlyBalanceTrend[monthIndex] = runningBalance;
          }

          const monthlyIncomeExpenseRatio = monthlyIncome.map(
            (incomeAmount, monthIndex) => {
              const expenseAmount = monthlyExpense[monthIndex];
              return expenseAmount > 0
                ? (incomeAmount / expenseAmount).toFixed(2)
                : 0;
            },
          );

          const buildMonthlySourceData = (transactions, transactionType) => {
            const sourceMap = {};
            transactions.forEach((transaction) => {
              if (transaction.type !== transactionType) return;
              const monthIndex = new Date(transaction.date).getMonth();
              const sourceName =
                transaction.source || `General ${transactionType}`;
              if (!sourceMap[sourceName]) {
                sourceMap[sourceName] = Array(12).fill(0);
              }
              sourceMap[sourceName][monthIndex] += parseFloat(
                transaction.amount || 0,
              );
            });
            return {
              labels: MONTH_NAMES,
              datasets: Object.keys(sourceMap).map((sourceName) => ({
                label: sourceName,
                data: sourceMap[sourceName],
              })),
            };
          };

          const incomeBySource = buildMonthlySourceData(
            yearlyTransactions,
            "Income",
          );
          const expenseBySource = buildMonthlySourceData(
            yearlyTransactions,
            "Expense",
          );
          const savingsBySource = buildMonthlySourceData(
            yearlyTransactions,
            "Savings",
          );

          const totalIncome = monthlyIncome.reduce(
            (sum, amount) => sum + amount,
            0,
          );
          const totalExpense = monthlyExpense.reduce(
            (sum, amount) => sum + amount,
            0,
          );
          const totalSavings = monthlySavings.reduce(
            (sum, amount) => sum + amount,
            0,
          );
          const savingsRate = totalIncome
            ? ((totalSavings / totalIncome) * 100).toFixed(1)
            : 0;

          let platformInsights = [];
          if (yearlyTransactions.length < 20) {
            platformInsights = [
              "Limited transaction data across the platform this year.",
              "Encourage users to log every income and expense for richer insights.",
              "Top tip: Set up automatic savings transfers on payday.",
            ];
          } else {
            const mostSpentCategory = Object.keys(categoryTotals).reduce(
              (a, b) => (categoryTotals[a] > categoryTotals[b] ? a : b),
              "Uncategorized",
            );
            platformInsights = [
              savingsRate >= 20
                ? `Platform-wide savings rate is strong at ${savingsRate}%.`
                : `Platform savings rate is low (${savingsRate}%). Consider launching savings challenges.`,
              `Most popular spending category: ${mostSpentCategory}`,
              totalExpense > totalIncome * 0.9
                ? "Platform is operating close to break-even. Monitor expenses closely."
                : "Overall healthy income-expense balance across all users.",
            ];
          }

          res.json({
            incomeVsExpenseBarData: {
              labels: MONTH_NAMES,
              datasets: [
                {
                  label: "Income",
                  data: monthlyIncome,
                  backgroundColor: "#4CAF50",
                },
                {
                  label: "Expense",
                  data: monthlyExpense,
                  backgroundColor: "#F44336",
                },
              ],
            },
            monthlyExpenseTrendLineData: {
              labels: MONTH_NAMES,
              datasets: [
                {
                  label: "Monthly Expenses",
                  data: monthlyExpense,
                  borderColor: "#FF6384",
                },
              ],
            },
            categorySpendingPieData: {
              labels: Object.keys(categoryTotals),
              datasets: [
                {
                  data: Object.values(categoryTotals),
                  backgroundColor: CHART_COLOR_PALETTE,
                },
              ],
            },
            balanceTrendLineData: {
              labels: MONTH_NAMES,
              datasets: [
                {
                  label: "Balance Trend",
                  data: monthlyBalanceTrend,
                  borderColor: "#2196F3",
                },
              ],
            },
            savingsGrowthLineData: {
              labels: MONTH_NAMES,
              datasets: [
                {
                  label: "Savings Growth",
                  data: monthlySavings,
                  borderColor: "#4CAF50",
                },
              ],
            },
            incomeBySourceBarData: incomeBySource,
            expensesBySourceBarData: expenseBySource,
            savingsBySourceBarData: savingsBySource,
            monthlyIncomeExpenseRatioLineData: {
              labels: MONTH_NAMES,
              datasets: [
                {
                  label: "Income/Expense Ratio",
                  data: monthlyIncomeExpenseRatio,
                  borderColor: "#FFCE56",
                },
              ],
            },
            financialSummaryData: {
              monthlyNets: monthlyIncome.map(
                (incomeAmount, monthIndex) =>
                  incomeAmount -
                  monthlyExpense[monthIndex] +
                  monthlySavings[monthIndex],
              ),
              yearlyIncome: totalIncome,
              yearlyExpense: totalExpense,
              yearlySavings: totalSavings,
              labels: MONTH_NAMES,
            },
            insights: platformInsights,
            totalUsers: await userCollection.countDocuments({}),
            totalTransactions: yearlyTransactions.length, 
          });
        } catch (err) {
          console.error("Admin Analytics Error:", err);
          res
            .status(500)
            .json({ error: "Failed to generate platform analytics" });
        }
      },
    );

    app.post("/admin/tips", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const newTip = {
          ...req.body,
          createdBy: req.decoded_email,
          createdAt: new Date(),
        };
        const result = await tipsCollection.insertOne(newTip);
        res.status(201).json(result);
      } catch (err) {
        res.status(500).json({ error: "Failed to add financial tip" });
      }
    });

    app.get("/admin/tips", verifyFBToken, verifyAdmin, async (req, res) => {
      const allTips = await tipsCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      res.json(allTips);
    });

    app.put("/admin/tips/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const result = await tipsCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: req.body },
      );
      res.json(result);
    });

    app.delete(
      "/admin/tips/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const result = await tipsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.json(result);
      },
    );

    app.get("/tips", async (req, res) => {
      try {
        const tips = await tipsCollection
          .find({})
          .sort({ createdAt: -1 })
          .limit(8)
          .toArray();
        res.json(tips);
      } catch (err) {
        res.status(500).json({ error: "Failed to fetch tips" });
      }
    });

    //--------Admin Dashboard Api End--------------

    //--------------User Api-------------------

    //--------------Income  Api------------------

    app.post("/income", verifyFBToken, async (req, res) => {
      try {
        const income = {
          ...req.body,
          createdByEmail: req.decoded_email,
          createdAt: new Date(),
        };
        const result = await incomeCollection.insertOne(income);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to create income entry" });
      }
    });
    app.get("/all-category", verifyFBToken, async (req, res) => {
      try {
        const categories = await categoryCollection
          .find({})
          .sort({ category: 1 })
          .toArray();

        res.status(200).send(categories);
      } catch (err) {
        res.status(500).send({ error: "Failed to fetch categories" });
      }
    });

    app.put("/update-income/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateIncome = req.body;
        delete updateIncome.createdByEmail;

        const query = { _id: new ObjectId(id) };
        const result = await incomeCollection.updateOne(query, {
          $set: updateIncome,
        });

        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update income entry" });
      }
    });
    app.patch("/patch-amount", verifyFBToken, async (req, res) => {
      const createdByEmail = req.decoded_email;
      const { id, amount, updatedAt } = req.body;
      const query = { createdByEmail, _id: new ObjectId(id) };
      const result = await incomeCollection.updateOne(query, {
        $set: { amount, updatedAt },
      });
      //console.log(result);
      res.send(result);
    });

    app.get("/income", verifyFBToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = 8;
        const skip = (page - 1) * limit;

        const income = await incomeCollection
          .find({ createdByEmail: req.decoded_email })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalIncomeSource = await incomeCollection.countDocuments({
          createdByEmail: req.decoded_email,
        });
        const totalIncomeCalculate = await incomeCollection
          .aggregate([
            {
              $match: {
                createdByEmail: req.decoded_email,
              },
            },
            {
              $group: {
                _id: null,
                total: { $sum: `$amount` },
              },
            },
          ])
          .toArray();
        const totalIncome = totalIncomeCalculate[0]?.total || 0;

        res.send({
          income,
          totalIncome,
          totalIncomeSource,
          currentPage: page,
          totalPages: Math.ceil(totalIncomeSource / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch income entries" });
      }
    });

    app.delete("/delete-income/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = {
          _id: new ObjectId(id),
          createdByEmail: req.decoded_email,
        };
        const result = await incomeCollection.deleteOne(query);
        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to delete income entry" });
      }
    });

    app.get("/income-track", verifyFBToken, async (req, res) => {
      const filterYear = req.query.year || new Date().getFullYear();

      try {
        const incomeStateTrack = await transactionCollection
          .aggregate([
            {
              $match: {
                createdByEmail: req.decoded_email,
                type: "Income",
                date: {
                  $gte: new Date(`${filterYear}-01-01`),
                  $lte: new Date(`${filterYear}-12-31`),
                },
              },
            },
            {
              $group: {
                _id: {
                  month: { $month: { $toDate: "$date" } },
                  source: "$source",
                },
                sourceAmount: { $sum: "$amount" },
              },
            },
            { $sort: { "_id.month": 1 } },
          ])
          .toArray();
        const monthNames = [
          "Jan",
          "Feb",
          "Mar",
          "Apr",
          "May",
          "Jun",
          "Jul",
          "Aug",
          "Sep",
          "Oct",
          "Nov",
          "Dec",
        ];

        const monthlyIncomeData = {};

        incomeStateTrack.forEach((item) => {
          const monthId = item._id.month;
          if (!monthlyIncomeData[monthId]) {
            monthlyIncomeData[monthId] = {
              monthId: monthId,
              month: monthNames[monthId - 1],
              totalMonthlyIncome: 0,
              sources: [],
            };
          }
          monthlyIncomeData[monthId].totalMonthlyIncome += item.sourceAmount;
          monthlyIncomeData[monthId].sources.push({
            sourceName: item._id.source,
            amount: item.sourceAmount,
          });
        });
        //console.log(monthlyIncomeData);
        res.status(200).send(Object.values(monthlyIncomeData));
      } catch (err) {
        res.status(500).send({ message: "Failed to track Income" });
      }
    });

    //-------------Transaction Api-------------------

    app.post("/transaction", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);

      if (user) {
        delete user._id;
        delete user.email;
        delete user.password;
        const body = { ...req.body };
        if (body._id) delete body._id;
        const transaction = {
          ...body,
          ...user,
          createdByEmail: email,
          createdAt: new Date(),
        };
        try {
          const result = await transactionCollection.insertOne(transaction);
          res.status(201).json({
            message: "Transaction created successfully",
            insertedId: result.insertedId,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: "Failed to create transaction" });
        }
      } else {
        res.status(404).json({ message: "User not found" });
      }
    });

    app.get("/transaction", verifyFBToken, async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = 8;
      const skip = (page - 1) * limit;
      const {
        search = "",
        category = "",
        type = "",
        sortField = "createdAt",
        sortOrder = "desc",
      } = req.query;

      const filter = { createdByEmail: req.decoded_email };

      if (search) {
        filter.$or = [
          { source: { $regex: search, $options: "i" } },
          { note: { $regex: search, $options: "i" } },
        ];
      }

      if (category) filter.category = category;
      if (type) filter.type = type;

      const sort = {};
      sort[sortField] = sortOrder === "asc" ? 1 : -1;

      try {
        const transactions = await transactionCollection
          .find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalTran = await transactionCollection.countDocuments(filter);

        res.status(200).send({
          transactions,
          totalTran,
          currentPage: page,
          totalPages: Math.ceil(totalTran / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch Transaction entries" });
      }
    });

    app.get("/recent-transactions", verifyFBToken, async (req, res) => {
      try {
        const query = { createdByEmail: req.decoded_email };
        const recentTransactions = await transactionCollection
          .find(query)
          .sort({ createdAt: -1 })
          .limit(5)
          .toArray();

        res.status(200).send(recentTransactions);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch recent transactions" });
      }
    });

    app.put("/update-transaction/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decoded_email;
        const updateTransaction = { ...req.body };
        //console.log(updateTransaction);
        delete updateTransaction.createdByEmail;

        const query = { _id: new ObjectId(id), createdByEmail: email };
        const result = await transactionCollection.updateOne(query, {
          $set: updateTransaction,
        });
        const updatedTransaction = await transactionCollection.findOne(query);
        res.status(200).json(updatedTransaction);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update Transaction entry" });
      }
    });

    app.delete("/delete-transaction/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decoded_email;
        const query = { _id: new ObjectId(id), createdByEmail: email };
        const result = await transactionCollection.deleteOne(query);
        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to delete transaction entry" });
      }
    });

    //--------------Expense Api-------------
    app.post("/expense", verifyFBToken, async (req, res) => {
      try {
        const expense = {
          ...req.body,
          createdByEmail: req.decoded_email,
          createdAt: new Date(),
        };
        const result = await expenseCollection.insertOne(expense);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to create expense entry" });
      }
    });

    app.put("/update-expense/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateExpense = req.body;
        delete updateExpense.createdByEmail; // Prevent overwriting ownership

        const query = { _id: new ObjectId(id) };
        const result = await expenseCollection.updateOne(query, {
          $set: updateExpense,
        });

        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update expense entry" });
      }
    });

    app.patch("/patch-expense-amount", verifyFBToken, async (req, res) => {
      try {
        const createdByEmail = req.decoded_email;
        const { id, amount, updatedAt } = req.body;

        const query = { createdByEmail, _id: new ObjectId(id) };
        const result = await expenseCollection.updateOne(query, {
          $set: { amount, updatedAt },
        });

        //console.log(result);
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update expense amount" });
      }
    });

    app.get("/expense", verifyFBToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = 8;
        const skip = (page - 1) * limit;

        const expenses = await expenseCollection
          .find({ createdByEmail: req.decoded_email })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalExpensesSource = await expenseCollection.countDocuments({
          createdByEmail: req.decoded_email,
        });

        const totalExpensesCalulate = await expenseCollection.aggregate([
          {
            $match: {
              createdByEmail: req.decoded_email,
            },
            $group: {
              _id: null,
              total: { $sum: `$amount` },
            },
          },
        ]);
        const totalExpenses = totalExpensesCalulate[0]?.total || 0;

        res.send({
          expenses,
          totalExpenses,
          totalExpensesSource,
          currentPage: page,
          totalPages: Math.ceil(totalExpenses / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch expense entries" });
      }
    });

    app.delete("/delete-expense/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await expenseCollection.deleteOne(query);
        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to delete expense entry" });
      }
    });

    app.get("/expense-track", verifyFBToken, async (req, res) => {
      const filterYear = req.query.year || new Date().getFullYear();
      const email = req.decoded_email;

      try {
        const expenseTrack = await transactionCollection
          .aggregate([
            {
              $match: {
                createdByEmail: email,
                type: "Expense",
                date: {
                  $gte: new Date(`${filterYear}-01-01`),
                  $lte: new Date(`${filterYear}-12-31`),
                },
              },
            },
            {
              $group: {
                _id: {
                  month: { $month: { $toDate: "$date" } },
                  source: "$source",
                },
                sourceAmount: { $sum: "$amount" },
              },
            },
            { $sort: { "_id.month": 1 } },
          ])
          .toArray();

        const monthNames = [
          "Jan",
          "Feb",
          "Mar",
          "Apr",
          "May",
          "Jun",
          "Jul",
          "Aug",
          "Sep",
          "Oct",
          "Nov",
          "Dec",
        ];

        const monthlyExpenseData = {};

        expenseTrack.forEach((item) => {
          const monthId = item._id.month;
          if (!monthlyExpenseData[monthId]) {
            monthlyExpenseData[monthId] = {
              monthId: monthId,
              month: monthNames[monthId - 1],
              totalMonthlyExpense: 0,
              sources: [],
            };
          }
          monthlyExpenseData[monthId].totalMonthlyExpense += item.sourceAmount;
          monthlyExpenseData[monthId].sources.push({
            sourceName: item._id.source,
            amount: item.sourceAmount,
          });
        });
        //console.log(monthlyExpenseData);

        res.status(200).send(Object.values(monthlyExpenseData));
      } catch (err) {
        res.status(500).send({ message: "Failed to track expenses" });
      }
    });

    //-------Savings Api--------
    app.post("/saving", verifyFBToken, async (req, res) => {
      try {
        const saving = {
          ...req.body,
          createdByEmail: req.decoded_email,
          createdAt: new Date(),
        };
        const result = await savingCollection.insertOne(saving);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to create income entry" });
      }
    });
    app.get("/saving", verifyFBToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = 8;
        const skip = (page - 1) * limit;

        const savings = await savingCollection
          .find({ createdByEmail: req.decoded_email })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalSavingsSource = await savingCollection.countDocuments({
          createdByEmail: req.decoded_email,
        });

        const totalSavingsCalulate = await savingCollection.aggregate([
          {
            $match: {
              createdByEmail: req.decoded_email,
            },
            $group: {
              _id: null,
              total: { $sum: `$amount` },
            },
          },
        ]);
        const totalSavings = totalSavingsCalulate[0]?.total || 0;

        res.send({
          savings,
          totalSavings,
          totalSavingsSource,
          currentPage: page,
          totalPages: Math.ceil(totalSavings / limit),
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch savings entries" });
      }
    });
    app.put("/update-saving/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateSaving = req.body;
        delete updateSaving.createdByEmail; // Prevent overwriting ownership

        const query = { _id: new ObjectId(id) };
        const result = await savingCollection.updateOne(query, {
          $set: updateSaving,
        });

        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update savings entry" });
      }
    });

    app.patch("/patch-saving-amount", verifyFBToken, async (req, res) => {
      const createdByEmail = req.decoded_email;
      const { id, amount, updatedAt } = req.body;

      const query = { createdByEmail, _id: new ObjectId(id) };
      const result = await savingCollection.updateOne(query, {
        $set: { amount, updatedAt },
      });

      //console.log(result);
      res.send(result);
    });
    app.delete("/delete-saving/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await savingCollection.deleteOne(query);
        res.status(200).json(result);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to delete savings entry" });
      }
    });

    app.get("/savings-track/:id", verifyFBToken, async (req, res) => {
      const targetId = req.params.id;
      const filterYear = req.query.year || new Date().getFullYear();

      try {
        const savingsTrack = await transactionCollection
          .aggregate([
            {
              $match: {
                targetID: targetId,
                createdByEmail: req.decoded_email,
                type: "Savings",
                date: {
                  $gte: new Date(`${filterYear}-01-01`),
                  $lte: new Date(`${filterYear}-12-31`),
                },
              },
            },
            {
              $group: {
                _id: {
                  month: { $month: { $toDate: "$date" } },
                  note: "$note",
                },
                contributionAmount: { $sum: "$amount" },
              },
            },
            { $sort: { "_id.month": 1 } },
          ])
          .toArray();
        const monthNames = [
          "Jan",
          "Feb",
          "Mar",
          "Apr",
          "May",
          "Jun",
          "Jul",
          "Aug",
          "Sep",
          "Oct",
          "Nov",
          "Dec",
        ];
        const monthlySavings = {};

        savingsTrack.forEach((item) => {
          const monthId = item._id.month;

          if (!monthlySavings[monthId]) {
            monthlySavings[monthId] = {
              monthId: monthId,
              month: monthNames[monthId - 1],
              totalMonthlySavings: 0,
              contributions: [],
            };
          }
          monthlySavings[monthId].totalMonthlySavings +=
            item.contributionAmount;
          monthlySavings[monthId].contributions.push({
            description: item._id.note || "Saving Deposit",
            amount: item.contributionAmount,
          });
        });
        res.status(200).send(Object.values(monthlySavings));
      } catch (error) {
        res.status(500).send({ message: "Failed to track savings progress" });
      }
    });

    //--------------USER Income Api End-----------------
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
