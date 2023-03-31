import { InferAttributes, InferCreationAttributes, Model, Optional } from "sequelize";
import { DataTypes, sequelize } from "../utils/connectDB";
import bcrypt from 'bcryptjs';

const saltRounds = 10;

export interface IUserModel extends Model<InferAttributes<IUserModel>, InferCreationAttributes<IUserModel>> {
    id?: string
    name: string;
    email: string;
    password: string;
    photo?: string;
    picture?: string;
    verified?: boolean;
    createdAt?: Date;
    updatedAt?: Date;
    provider?: String;
    comparePassword: (candidatePassword: string, hashedPassword: string) => boolean
}

const UserModel = sequelize.define<IUserModel>("users", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    photo: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: "default.png"
    },
    verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    },
    createdAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: sequelize.literal('NOW()')
    },
    provider: {
        type: DataTypes.STRING,
        allowNull: true
    },
    updatedAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: sequelize.literal('NOW()')
    }
}, {
    timestamps: false
})

UserModel.beforeSave(async (user) => {
    if (user.changed("password")) {
        user.password = await bcrypt.hash(user.password, bcrypt.genSaltSync(saltRounds))
    }
})

UserModel.prototype.comparePassword = async (candidatePassword: string, hashedPassword: string) => {
    return await bcrypt.compare(candidatePassword, hashedPassword);
};

export default UserModel;