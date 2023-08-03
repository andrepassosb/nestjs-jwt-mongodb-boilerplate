import { Injectable, Inject } from '@nestjs/common';
import { Model } from 'mongoose';
import { RegisterDto } from './dto/register-auth.dto';
import { LoginDto } from './dto/login-auth.dto';
import { ChangePasswordDto } from './dto/change-password-auth.dto';
import { User } from 'src/users/schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { IUserPayload } from '../users/interfaces/user.interface';

@Injectable()
export class AuthService {
  constructor(@Inject('USER_MODEL') private readonly userModel: Model<User>) {}

  async register(body: RegisterDto) {
    // Hashed password
    const password = body.password;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create Payload
    const payload: IUserPayload = {
      name: body.name,
      email: body.email,
      password: hashedPassword,
    };

    const createdUser = await this.userModel.create(payload);
    const result = {
      id: createdUser._id,
      name: createdUser.name,
      email: createdUser.email,
    };
    return result;
  }

  login(loginDto: LoginDto) {
    return 'This action adds a new auth';
  }
  changePassword(changePasswordDto: ChangePasswordDto) {
    return 'This action adds a new auth';
  }
}
