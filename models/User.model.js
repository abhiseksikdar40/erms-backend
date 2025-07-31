const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    userName: { type: String, required: true},
    userEmail: { type: String, required: true, unique: true},
    userPassword: { type: String, required: true},
    userRole: { type: String, enum: ["Engineer", "Manager"], required: true},
    // For Engineer Fields ↓
    userSkills: [{ type: String}],
    userSeniority: { type: String, enum: ["Junior", "Mid", "Senior"]},
    maxCapacity: { type: Number},
    userDepartment: { type: String}
},
{
    timestamps: true
}
)

const User = mongoose.model('User', UserSchema)
module.exports = User