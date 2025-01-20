const mongoose = require('mongoose');

const connectDb = async () => {
  try {

    const DB_OPTIONS = {
      dbName: 'CRUD_OPT',
    };


    await mongoose.connect(process.env.DATABASE_URL, DB_OPTIONS);

    console.log("Database connected successfully!");
  } catch (error) {
    console.error("Error while connecting to the database:", error.message);
  }
};

module.exports = connectDb;
