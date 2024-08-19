import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ApiKey } from 'src/common/entities/apiKeys';

@Module({
  imports: [
    TypeOrmModule.forFeature([ApiKey]),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'mySecretKey', // Usa una variable de entorno para mayor seguridad
      signOptions: { expiresIn: '60m' }, // El token expira en 60 minutos
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
