import { PickType } from '@nestjs/mapped-types';
import { CreateUserDto } from '../../users/dto/create-user.dto';

export class ChangePasswordDto extends PickType(CreateUserDto, [
  'password',
] as const) {}
