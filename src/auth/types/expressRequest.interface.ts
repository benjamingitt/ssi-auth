import {UsersEntity} from '@app/auth/users.entity';
import {Request} from 'express'

export interface ExpressRequest extends Request {
  user?: UsersEntity
}
