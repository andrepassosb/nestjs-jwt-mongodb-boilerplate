import { PartialType } from '@nestjs/mapped-types';
import { RegisterDto } from './register-auth.dto';

export class LoginDto extends PartialType(RegisterDto) {}
