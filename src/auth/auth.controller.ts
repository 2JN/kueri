import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { JwtGuard } from './guard';
import { RefreshGuard } from './guard/refresh.guard';
import { AuthUser } from './decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(dto);
  }

  @UseGuards(JwtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('signout')
  signOut(@AuthUser('id') userId: number) {
    return this.authService.signOut(userId);
  }

  @UseGuards(RefreshGuard)
  @HttpCode(HttpStatus.OK)
  @Post('refresh-token')
  refreshToken(@AuthUser() user) {
    return this.authService.refreshToken(user.sub, user.refreshToken);
  }
}
