import { IsNotEmpty } from "class-validator";

export class LoginUserDto {

    @IsNotEmpty()
    readonly signatureHex: string;

    @IsNotEmpty()
    readonly did: string;
    message: string;
}