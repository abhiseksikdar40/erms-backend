const mongoose = require('mongoose');

const ProjectSchema = new mongoose.Schema(
  {
    projectName: { type: String, required: true },
    projectDescription: { type: String },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    requiredSkills: [{ type: String, required: true }],
    teamSize: { type: Number },
    projectStatus: {
      type: String,
      enum: ["Planning", "Active", "Completed"],
      default: "Planning"
    },
    managerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    assignedEngineers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
  },
  {
    timestamps: true
  }
);

const Project = mongoose.model('Project', ProjectSchema);
module.exports = Project;
