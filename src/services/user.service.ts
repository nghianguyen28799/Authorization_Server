import UserModel from "../models/user.model";
import { CreateUserInput } from "../schemas/user.schema";

interface IOAuthGoogle {
    name: string;
    email: string;
    picture: string;
}

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

export const findUserByEmailService = async (email: string) => {
    const user = await UserModel.findOne({ where: { email } });

    return user;
}

export const findUserByPkService = async (pk: string) => {
    const user = await UserModel.findByPk(pk);

    return user;
}

export const UpsertByEmailService = async (input: IOAuthGoogle) => {
    const { email, name, picture } = input;

    const user = await findUserByEmailService(email);

    let upsertUser;

    if (user) {
        upsertUser = await UserModel.update({
            ...user,
            provider: 'Google',
            verified: true,
        }, {
            where: {
                email
            }
        })
    } else {
        upsertUser = await UserModel.create({
            name,
            email: email.toLowerCase(),
            password: '',
            verified: true,
            provider: 'Google',
            picture: picture
        })
    }

    return upsertUser
}