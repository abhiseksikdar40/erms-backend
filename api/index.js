const express = require("express");
require("dotenv").config();
const serverless = require("serverless-http");
const cors = require("cors");
const JWT = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const Project = require("../models/Project.models");
const Task = require("../models/Task.model");
const User = require("../models/User.model");
const { resourceManagementData } = require("../db/db.connect");

const app = express();
resourceManagementData();
app.use(express.json());

// --- CORS ---
app.use(cors({
  origin: ["http://localhost:5173", "https://erms-frontend-g9oz.vercel.app"],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));



// --- JWT Middleware ---
const JWT_SECRET = process.env.JWT_KEY;
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No Token Provided or Invalid Format!" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = JWT.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("JWT validation failed:", err.message);
    return res.status(403).json({ message: "Invalid Token!" });
  }
};

// --- Auth Routes ---
app.post("/v1/signup", async (req, res) => {
  try {
    const {
      userName,
      userEmail,
      userPassword,
      userRole,
      userSkills,
      userSeniority,
      userDepartment,
      maxCapacity,
    } = req.body;

    if (!userName || !userEmail || !userPassword || !userRole) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    const existingUser = await User.findOne({ userEmail });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(userPassword, 10);

    const newUser = new User({
      userName,
      userEmail,
      userPassword: hashedPassword,
      userRole,
      userSkills: userSkills || [],
      userSeniority,
      userDepartment,
      maxCapacity: maxCapacity ? Number(maxCapacity) : undefined,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("SIGNUP ERROR:", error);
    res.status(500).json({ message: "Registration failed", error: error.message });
  }
});


app.post("/v1/login", async (req, res) => {
  try {
    const { userEmail, userPassword } = req.body;

    if (!userEmail || !userPassword) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ userEmail });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(userPassword, user.userPassword);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const JWT_SECRET = process.env.JWT_KEY;
    if (!JWT_SECRET) {
      console.error("Missing JWT_SECRET at runtime");
      return res.status(500).json({ message: "Server misconfigured: JWT_SECRET missing" });
    }

    const token = JWT.sign(
      { id: user._id, email: user.userEmail, userRole: user.userRole },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});



app.get("/v1/auth/me", verifyJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-userPassword");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/v1/auth/update/me", verifyJWT, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      req.body,
      { new: true, runValidators: true, select: "-userPassword" }
    );
    if (!updatedUser) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User updated successfully", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Failed to update user" });
  }
});

// Fetch all engineers (protected route)
app.get("/v1/auth/engineers", verifyJWT, async (req, res) => {
  try {
    if (req.user.userRole !== "Manager") {
      return res.status(403).json({ message: "Only managers can view engineers" });
    }

    const engineers = await User.find({ userRole: "Engineer" })
      .select("userName userSkills maxCapacity");

    res.status(200).json({ users: engineers });
  } catch (error) {
    console.error("Error fetching engineers:", error.message);
    res.status(500).json({ message: "Failed to fetch engineers" });
  }
});



// --- Project Routes ---
app.post("/v1/auth/projects", verifyJWT, async (req, res) => {
  try {
    if (req.user.userRole !== "Manager") return res.status(403).json({ message: "Only managers can create projects" });
    const newProject = new Project({ ...req.body, managerId: req.user.id });
    const savedProject = await newProject.save();
    res.status(201).json({ message: "Project created successfully", project: savedProject });
  } catch (error) {
    res.status(500).json({ message: "Failed to create project" });
  }
});

app.get("/v1/auth/projects", verifyJWT, async (req, res) => {
  try {
    let projects;
    if (req.user.userRole === "Manager") {
      projects = await Project.find({ managerId: req.user.id }).populate("managerId");
    } else if (req.user.userRole === "Engineer") {
      projects = await Project.find({ assignedEngineers: req.user.id }).populate("managerId");
    } else {
      return res.status(403).json({ message: "Unauthorized" });
    }
    res.status(200).json({projects});
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch projects" });
  }
});


app.post("/v1/auth/update/projects/:id", verifyJWT, async (req, res) => {
  try {
    if (req.user.userRole !== "Manager") return res.status(403).json({ message: "Only managers can update projects" });
    const updatedProject = await Project.findOneAndUpdate(
      { _id: req.params.id, managerId: req.user.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!updatedProject) return res.status(404).json({ message: "Project not found or unauthorized" });
    res.status(200).json({ message: "Project updated successfully", project: updatedProject });
  } catch (error) {
    res.status(500).json({ message: "Failed to update project" });
  }
});



// --- TASK ROUTES ---
app.post("/v1/auth/tasks", verifyJWT, async (req, res) => {
  try {
    if (req.user.userRole !== "Manager") {
      return res.status(403).json({ message: "Only managers can assign tasks" });
    }

    const { engineerId, projectId, allocationPercentage, startDate, endDate } = req.body;

    const project = await Project.findOne({ _id: projectId, managerId: req.user.id });
    if (!project) {
      return res.status(404).json({ message: "Project not found or unauthorized" });
    }

    // Automatically assign engineer to project if not already assigned
    if (!project.assignedEngineers.includes(engineerId)) {
      project.assignedEngineers.push(engineerId);
      await project.save();
    }

    const task = new Task({ engineerId, projectId, allocationPercentage, startDate, endDate });
    await task.save();

    res.status(201).json({ message: "Task assigned successfully", task });
  } catch (error) {
    res.status(500).json({ message: "Failed to assign task", error: error.message });
  }
});

app.get("/v1/auth/tasks", verifyJWT, async (req, res) => {
  try {
    let tasks = [];

    if (req.user.userRole === "Manager") {
      // Fetch projects managed by this manager
      const projects = await Project.find({ managerId: req.user.id });

      if (!projects.length) {
        return res.status(200).json([]); // No projects → no tasks
      }

      const projectIds = projects.map((project) => project._id);

      // Fetch tasks for these projects
      tasks = await Task.find({ projectId: { $in: projectIds } })
        .populate("projectId", "projectName projectStatus")
        .populate("engineerId", "userName maxCapacity");
    } else {
      // If user is Engineer, fetch only their tasks
      tasks = await Task.find({ engineerId: req.user.id })
        .populate("projectId", "projectName projectStatus");
    }

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Failed to fetch tasks:", error);
    res.status(500).json({ message: "Failed to fetch tasks", error: error.message });
  }
});




module.exports = app;
module.exports.handler = serverless(app);