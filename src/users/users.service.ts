import { Inject, Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './schemas/user.schema';
@Injectable()
export class UsersService {
  constructor(@Inject('USER_MODEL') private readonly userModel: Model<User>) {}

  findAll() {
    return this.userModel.find().exec();
  }

  findOne(id: string) {
    return this.userModel.find({ _id: id });
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
