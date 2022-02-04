import { JWT_SECRET } from '@app/config';
import { Body, Controller, Get, Post, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from './decorator/user.decorator';
import { CreateUserDto } from './dto/createUser.dto';
import { LoginUserDto } from './dto/login.dto';
import { AuthGuard } from './guards/auth.guard';
import { UserResponseInterface } from './types/userResponse.interface';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService){}
    
    @Post()
    @UsePipes(new ValidationPipe())
    async createUser(
        @Body('user') createUserDto: CreateUserDto
        ): Promise<any> {
        const user = await this.authService.createVerify(createUserDto);
        return user
    }

    @Post('login')
    @UsePipes(new ValidationPipe())
    async login(
        @Body('user') loginUserDto: LoginUserDto
        ): Promise<UserResponseInterface> {
        const user = await this.authService.login(loginUserDto);
        return this.authService.buildUserResponse(user)
    }


    @Post('didadrr')
    @UseGuards(AuthGuard)
    async getDid(
        @Body() did: any
        ): Promise<any> {
            console.log(did)
        const val = await this.authService.getDidContract(did);
        return val
    }

    @Post('diddoc')
    @UseGuards(AuthGuard)
    async getDidDoc(
        @Body() did: any
        ): Promise<any> {
        const val = await this.authService.getDidDoc(did);
        return val
    }

    @Post('signature')
    async signHex(
        @Body() sign: any
        ): Promise<any> {
        const val = await this.authService.signMessage(sign);
        return val
    }

    @Post('decode')
    async verifyDecode(
        @Body() sign: any
        ): Promise<any> {
        const val = await this.authService.verifyMessage(sign);
        return val
    }

    @Post('jwt')
    async jwtRead(
        @Body() jwt: any
        ): Promise<any> {
        console.log(jwt)
        return await this.authService.jwtRead(jwt);
    }
}
