import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

import { AuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { Tokens } from './types';
import { Payload } from './types/payload.type';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signUp(dto: AuthDto): Promise<Tokens> {
    try {
      const password = await bcrypt.hash(dto.password, 8);
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password,
        },
      });

      const tokens = await this.signToken(user.id, user.email);
      await this.updateRTHash(user.id, tokens.refresh_token);

      return tokens;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002')
          throw new ForbiddenException('Credentials taken');
      }

      throw error;
    }
  }

  async signIn(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Credentials incorrect');

    const pwMatches = await bcrypt.compare(dto.password, user.password);

    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    const tokens = await this.signToken(user.id, user.email);
    await this.updateRTHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async signOut(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        refresh_token: {
          not: null,
        },
      },
      data: {
        refresh_token: null,
      },
    });
  }

  async refreshToken(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.refresh_token)
      throw new ForbiddenException('Access Denied');

    const rtMatches = await bcrypt.compare(refreshToken, user.refresh_token);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.signToken(user.id, user.email);
    await this.updateRTHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async signToken(userId: number, email: string): Promise<Tokens> {
    const payload: Payload = {
      sub: userId,
      email,
    };

    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: this.config.get('JWT_SECRET'),
      }),
      this.jwt.signAsync(payload, {
        expiresIn: '7d',
        secret: this.config.get('REFRESH_SECRET'),
      }),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }

  async updateRTHash(userId: number, refreshToken: string) {
    const token = await bcrypt.hash(refreshToken, 8);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refresh_token: token,
      },
    });
  }
}
