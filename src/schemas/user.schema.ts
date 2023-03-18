import { TypeOf, z } from "zod";

export const createUserSchema = z.object({
    body: z.object({
        name: z.string({
            required_error: 'Name is required',
        }),
        email: z.string({
            required_error: 'Email is required',
        }),
        password: z.string({
            required_error: 'Password is required',
        }).min(8, "Password must be more than 8 characters")
            .max(32, "Password must be less then 32 characters"),
        passwordConfirm: z.string({
            required_error: 'Confirm Password is required',
        }),
    }).refine((data) => data.password === data.passwordConfirm, {
        path: ['passwordConfirm'],
        message: 'Passwords do not match'
    })
})

export const loginUserSchema = z.object({
    body: z.object({
        email: z.string({
            required_error: "Email address is required"
        }).email("Invalid email address"),
        password: z.string({
            required_error: "Password is required"
        }).min(8, "Invalid email or password")
    })
})

export type CreateUserInput = Omit<
    TypeOf<typeof createUserSchema>['body'],
    'passwordConfirm'
>;
export type LoginUserInput = TypeOf<typeof loginUserSchema>['body']