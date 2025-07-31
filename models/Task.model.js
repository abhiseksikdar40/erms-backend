const mongoose = require('mongoose')

const TaskSchema = new mongoose.Schema({
  engineerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  projectId:  { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },
  allocationPercentage: { type: Number },
  startDate: { type: Date },
  endDate: { type: Date }
}, {
  timestamps: true
});


const Task = mongoose.model('Task', TaskSchema)

module.exports = Task