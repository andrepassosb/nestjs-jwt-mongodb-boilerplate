import { Document } from 'mongoose';

export interface User extends Document {
  readonly name: string;
  readonly email: string;
  readonly password: string;
}

export interface IUserPayload {
  name: string;
  email: string;
  password: string;
  id?: string;
}
