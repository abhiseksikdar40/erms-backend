const mongoose  = require('mongoose')
require('dotenv').config()

const  mongoUrl = process.env.MONGO_URL

const resourceManagementData = async () => {
    try {
        await mongoose.connect(mongoUrl)
        console.log("Database Connected")
    } catch (error) {
        console.log("Error Occured While Connecting Database!", error)
    }
}

module.exports = { resourceManagementData }