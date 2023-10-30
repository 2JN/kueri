import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Payload } from '../types/payload.type';

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: Payload) {
    const refreshToken = req.get('Authorization').replace('Bearer', '').trim();

    return {
      ...payload,
      refreshToken,
    };
  }
}
