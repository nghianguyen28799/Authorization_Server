import { Sequelize, DataTypes } from 'sequelize'

require("dotenv").config();

const sequelize = new Sequelize(process.env.DATABASE_URL as string);

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log("Connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }
};

export { connectDB, sequelize, Sequelize, DataTypes }