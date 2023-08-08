import {
  Injectable,
  Inject,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { RegisterDto } from './dto/register-auth.dto';
import { LoginDto } from './dto/login-auth.dto';
import { ChangePasswordDto } from './dto/change-password-auth.dto';
import { User } from 'src/users/schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { IUserPayload } from '../users/interfaces/user.interface';
import { JwtPayload, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @Inject('USER_MODEL') private readonly userModel: Model<User>,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  saltRounds = 10;

  async register(body: RegisterDto) {
    // Hashed password
    const password = body.password;
    const hashedPassword = await bcrypt.hash(password, this.saltRounds);

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

  async login(body: LoginDto): Promise<Tokens> {
    const user = await this.userModel.findOne({ email: body.email });

    if (!user) {
      throw new NotFoundException('No account with this email was found');
    }

    const decode = await bcrypt.compare(body.password, user.password);

    if (!decode) {
      throw new UnauthorizedException('Authentication failed. Wrong password');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string): Promise<boolean> {
    await this.updateRtHash(userId, null);
    return true;
  }

  async changePassword(userId: string, body: ChangePasswordDto) {
    const passwordHash = await bcrypt.hash(body.password, this.saltRounds);
    await this.userModel.updateOne({ _id: userId }, { password: passwordHash });
    return {
      message: 'Password changed successfully',
    };
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async refreshTokens(userId: number, rt: string): Promise<Tokens> {
    const user = await this.userModel.findById(userId);
    if (!user || !user.refreshTokenHash)
      throw new ForbiddenException('Access Denied');

    const rtMatches = await bcrypt.compare(rt, user.refreshTokenHash);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    // compare date created refresh token with date created token
    const iatRt = this.jwtService.decode(rt)['iat'];
    const iatToken = user.refreshTokenIat;
    if (iatRt < iatToken) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: string, rt: string): Promise<void> {
    if (!rt) {
      await this.userModel.updateOne(
        { _id: userId },
        { refreshTokenHash: null, refreshTokenIat: null },
      );
      return;
    }
    const rtHash = await bcrypt.hash(rt, this.saltRounds);
    const rtIat = this.jwtService.decode(rt)['iat'];
    await this.userModel.updateOne(
      { _id: userId },
      { refreshTokenHash: rtHash, refreshTokenIat: rtIat },
    );
  }
}
