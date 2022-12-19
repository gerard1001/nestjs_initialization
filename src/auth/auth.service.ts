import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { throwError } from 'rxjs';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    //generate password hash
    const hash = await argon.hash(dto.password);
    //save the new user in the db

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        // select: {
        //   id: true,
        //   email: true,
        //   createdAt: true,
        // },
      });
      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
    }
  }
  async login(dto: AuthDto) {
    //find the user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });
    //if user not exist error
    if (!user) {
      throw new ForbiddenException('Incorrect credentials');
    }
    //compare passowrd
    const pwdCompare = await argon.verify(user.hash, dto.password);
    //if password incorrect throw exception
    if (!pwdCompare) {
      throw new ForbiddenException('Password incorrect');
    }
    delete user.hash;
    //send back the user
    return user;
  }
}
