require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===============================
// DATABASE
// ===============================

const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb://127.0.0.1:27017/tournament_app";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "tournament_app_secret_change_me";

// ===============================
// USER MODEL
// ===============================

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    phone: {
      type: String,
      default: ""
    },

    walletBalance: {
      type: Number,
      default: 0
    },

    totalWinnings: {
      type: Number,
      default: 0
    },

    totalDeposited: {
      type: Number,
      default: 0
    },

    totalWithdrawn: {
      type: Number,
      default: 0
    },

    tournamentsJoined: {
      type: Number,
      default: 0
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    status: {
      type: String,
      enum: ["active", "blocked"],
      default: "active"
    }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ===============================
// TOURNAMENT MODEL
// ===============================

const tournamentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true
    },

    game: {
      type: String,
      required: true
    },

    banner: {
      type: String,
      default: ""
    },

    description: {
      type: String,
      default: ""
    },

    entryFee: {
      type: Number,
      default: 0
    },

    prizePool: {
      type: Number,
      default: 0
    },

    maxPlayers: {
      type: Number,
      default: 100
    },

    joinedPlayers: {
      type: Number,
      default: 0
    },

    startTime: {
      type: Date,
      required: true
    },

    endTime: {
      type: Date
    },

    roomId: {
      type: String,
      default: ""
    },

    roomPassword: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "upcoming",
        "live",
        "completed",
        "cancelled"
      ],
      default: "upcoming"
    }
  },
  { timestamps: true }
);

const Tournament = mongoose.model(
  "Tournament",
  tournamentSchema
);

// ===============================
// TRANSACTION MODEL
// ===============================

const transactionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    },

    type: {
      type: String,
      enum: [
        "deposit",
        "entry_fee",
        "winning",
        "withdrawal",
        "refund"
      ]
    },

    amount: {
      type: Number,
      required: true
    },

    status: {
      type: String,
      enum: [
        "pending",
        "success",
        "failed",
        "rejected"
      ],
      default: "pending"
    },

    description: {
      type: String,
      default: ""
    },

    reference: {
      type: String,
      default: ""
    }
  },
  { timestamps: true }
);

const Transaction = mongoose.model(
  "Transaction",
  transactionSchema
);

// ===============================
// WITHDRAWAL MODEL
// ===============================

const withdrawalSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    },

    amount: {
      type: Number,
      required: true
    },

    method: {
      type: String,
      enum: ["upi", "bank"],
      default: "upi"
    },

    upiId: {
      type: String,
      default: ""
    },

    accountHolderName: {
      type: String,
      default: ""
    },

    accountNumber: {
      type: String,
      default: ""
    },

    ifsc: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "pending",
        "approved",
        "rejected"
      ],
      default: "pending"
    },

    adminNote: {
      type: String,
      default: ""
    }
  },
  { timestamps: true }
);

const Withdrawal = mongoose.model(
  "Withdrawal",
  withdrawalSchema
);

// ===============================
// AUTH MIDDLEWARE
// ===============================

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({
        success: false,
        message: "Login required"
      });
    }

    const token = header.replace("Bearer ", "");

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}

// ===============================
// HEALTH CHECK
// ===============================

app.get("/api", (req, res) => {
  res.json({
    success: true,
    message: "Tournament App API is working"
  });
});

// ===============================
// REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      phone
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    const existingUser = await User.findOne({
      email
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already registered"
      });
    }

    const hashedPassword =
      await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      phone
    });

    res.status(201).json({
      success: true,
      message: "Registration successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const user = await User.findOne({
      email
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    if (user.status === "blocked") {
      return res.status(403).json({
        success: false,
        message: "Your account is blocked"
      });
    }

    const passwordMatch =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ===============================
// GET CURRENT USER
// ===============================

app.get(
  "/api/auth/me",
  auth,
  async (req, res) => {
    try {
      const user = await User.findById(
        req.user.id
      ).select("-password");

      res.json({
        success: true,
        user
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// TOURNAMENT LIST
// ===============================

app.get(
  "/api/tournaments",
  async (req, res) => {
    try {
      const tournaments =
        await Tournament.find()
          .sort({ startTime: 1 });

      res.json({
        success: true,
        tournaments
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// SINGLE TOURNAMENT
// ===============================

app.get(
  "/api/tournaments/:id",
  async (req, res) => {
    try {
      const tournament =
        await Tournament.findById(
          req.params.id
        );

      if (!tournament) {
        return res.status(404).json({
          success: false,
          message: "Tournament not found"
        });
      }

      res.json({
        success: true,
        tournament
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// ADMIN CREATE TOURNAMENT
// ===============================

app.post(
  "/api/admin/tournaments",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const tournament =
        await Tournament.create(req.body);

      res.status(201).json({
        success: true,
        message: "Tournament created",
        tournament
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// ADMIN UPDATE TOURNAMENT
// ===============================

app.put(
  "/api/admin/tournaments/:id",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const tournament =
        await Tournament.findByIdAndUpdate(
          req.params.id,
          req.body,
          {
            new: true,
            runValidators: true
          }
        );

      if (!tournament) {
        return res.status(404).json({
          success: false,
          message: "Tournament not found"
        });
      }

      res.json({
        success: true,
        message: "Tournament updated",
        tournament
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// ADMIN DELETE TOURNAMENT
// ===============================

app.delete(
  "/api/admin/tournaments/:id",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      await Tournament.findByIdAndDelete(
        req.params.id
      );

      res.json({
        success: true,
        message: "Tournament deleted"
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// JOIN TOURNAMENT
// ===============================

app.post(
  "/api/tournaments/:id/join",
  auth,
  async (req, res) => {
    try {
      const tournament =
        await Tournament.findById(
          req.params.id
        );

      const user =
        await User.findById(req.user.id);

      if (!tournament) {
        return res.status(404).json({
          success: false,
          message: "Tournament not found"
        });
      }

      if (tournament.status !== "upcoming") {
        return res.status(400).json({
          success: false,
          message: "Tournament is not open for joining"
        });
      }

      if (
        tournament.joinedPlayers >=
        tournament.maxPlayers
      ) {
        return res.status(400).json({
          success: false,
          message: "Tournament is full"
        });
      }

      if (
        user.walletBalance <
        tournament.entryFee
      ) {
        return res.status(400).json({
          success: false,
          message: "Insufficient wallet balance"
        });
      }

      user.walletBalance -=
        tournament.entryFee;

      user.tournamentsJoined += 1;

      tournament.joinedPlayers += 1;

      await user.save();
      await tournament.save();

      await Transaction.create({
        user: user._id,
        type: "entry_fee",
        amount: tournament.entryFee,
        status: "success",
        description:
          `Entry fee for ${tournament.title}`
      });

      res.json({
        success: true,
        message: "Tournament joined successfully",
        walletBalance:
          user.walletBalance
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// WALLET
// ===============================

app.get(
  "/api/wallet",
  auth,
  async (req, res) => {
    try {
      const user =
        await User.findById(req.user.id)
          .select(
            "walletBalance totalWinnings totalDeposited totalWithdrawn"
          );

      const transactions =
        await Transaction.find({
          user: req.user.id
        }).sort({
          createdAt: -1
        });

      res.json({
        success: true,
        wallet: user,
        transactions
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// WITHDRAWAL REQUEST
// ===============================

app.post(
  "/api/withdrawals",
  auth,
  async (req, res) => {
    try {
      const {
        amount,
        method,
        upiId,
        accountHolderName,
        accountNumber,
        ifsc
      } = req.body;

      const user =
        await User.findById(req.user.id);

      if (!amount || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid amount"
        });
      }

      if (user.walletBalance < amount) {
        return res.status(400).json({
          success: false,
          message: "Insufficient balance"
        });
      }

      user.walletBalance -= amount;

      await user.save();

      const withdrawal =
        await Withdrawal.create({
          user: user._id,
          amount,
          method,
          upiId,
          accountHolderName,
          accountNumber,
          ifsc
        });

      await Transaction.create({
        user: user._id,
        type: "withdrawal",
        amount,
        status: "pending",
        description: "Withdrawal request"
      });

      res.json({
        success: true,
        message:
          "Withdrawal request submitted",
        withdrawal
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ===============================
// ADMIN DASHBOARD
// ===============================

app.get(
  "/api/admin/dashboard",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const totalUsers =
        await User.countDocuments({
          role: "user"
        });

      const activeUsers =
        await User.countDocuments({
          role: "user",
          status: "active"
        });

      const totalTournaments =
        await Tournament.countDocuments();

      const activeTournaments =
        await Tournament.countDocuments({
          status: {
            $in: ["upcoming", "live"]
          }
        });

      const successfulEntries =
        await Transaction.find({
          type: "entry_fee",
          status: "success"
        });

      const totalEntryFees =
        successfulEntries.reduce(
          (sum, item) => sum + item.amount,
          0
        );

      const deposits =
        await Transaction.find({
          type: "deposit",
          status: "success"
        });

      const totalDeposits =
        deposits.reduce(
          (sum, item) =>
