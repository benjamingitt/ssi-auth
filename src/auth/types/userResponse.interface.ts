import { UsersEntity } from "../users.entity";

export interface UserResponseInterface {
    user: UsersEntity & {token: string};
}