import UserModel from "../models/user.model";
import { CreateUserInput } from "../schemas/user.schema";

export const registerUserService = async (input: CreateUserInput) => {
    const { name, password, email } = input;
    const user = await UserModel.create({
        name, password, email: email.toLowerCase()
    });

    return {
        ...user.get(),
        password: undefined
    }
}

export const findUserByEmail = async (email: string) => {
    const user = await UserModel.findOne({ where: { email } });

    return user;
}

export const findUserByPk = async (pk: string) => {
    const user = await UserModel.findByPk(pk);

    return user;
}