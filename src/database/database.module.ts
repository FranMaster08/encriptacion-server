import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ApiKey } from '../common/entities/apiKeys';

@Module({
  imports: [
    ConfigModule.forRoot(), // Para acceder a variables de entorno si las necesitas
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'sqlite',
        database:
          configService.get<string>('DATABASE_NAME') || 'database.sqlite',
        entities: [ApiKey], // Aquí puedes incluir todas tus entidades
        synchronize: true, // ¡Solo para desarrollo! No lo uses en producción
      }),
    }),
    TypeOrmModule.forFeature([ApiKey]), // Importa el repositorio de ApiKey
  ],
  exports: [TypeOrmModule], // Exporta TypeOrmModule para usarlo en otros módulos
})
export class DatabaseModule {}
