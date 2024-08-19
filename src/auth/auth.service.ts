import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ApiKey } from 'src/common/entities/apiKeys';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(ApiKey)
    private readonly apiKeyRepository: Repository<ApiKey>,
    private readonly jwtService: JwtService, // Inyectar el servicio JWT
  ) {}

  // Método para validar una ApiKey y descifrar un texto usando la clave privada
  public async validarYDescifrar(
    apiKey: string,
    encryptedText: string,
  ): Promise<string> {
    console.log(`Validando la API Key: ${apiKey}`);

    // Busca la API Key en la base de datos
    const key = await this.apiKeyRepository.findOne({
      where: { nameApiKey: apiKey, enabled: true },
    });

    if (!key) {
      console.warn(`API Key inválida o deshabilitada: ${apiKey}`);
      throw new UnauthorizedException(`API Key inválida o deshabilitada`);
    }

    try {
      const decryptedText = crypto.privateDecrypt(
        key.privateKey,
        Buffer.from(encryptedText, 'base64'),
      );

      // Reiniciar el contador de intentos fallidos si el descifrado es exitoso
      if (key.failedAttempts > 0) {
        key.failedAttempts = 0;
        await this.apiKeyRepository.save(key);
      }

      return decryptedText.toString('utf8');
    } catch (error) {
      console.error(
        `Error al descifrar el texto con la API Key: ${apiKey}`,
        error,
      );

      // Incrementar el contador de intentos fallidos
      key.failedAttempts += 1;

      if (key.failedAttempts >= 3) {
        key.enabled = false;
        console.warn(
          `La API Key ${apiKey} ha sido deshabilitada debido a múltiples intentos fallidos`,
        );
      }

      await this.apiKeyRepository.save(key);

      throw new UnauthorizedException(
        `Clave pública incorrecta. Posible intento de acceso peligroso.`,
      );
    }
  }

  public async validarApiKey(apiKey: string): Promise<boolean> {
    const key = await this.apiKeyRepository.findOne({
      where: { nameApiKey: apiKey },
    });

    if (!key || !key.enabled) {
      throw new UnauthorizedException(`API Key no válida o deshabilitada`);
    }

    return !!key;
  }

  public async listarApiKeys() {
    try {
      return await this.apiKeyRepository.find();
    } catch (error) {
      console.error('Error al listar las API Keys', error);
      throw new InternalServerErrorException('Error al listar las API Keys');
    }
  }

  public async createApiKey(
    name: string,
  ): Promise<{ nameApiKey: string; publicKey: string }> {
    // Primero, verifica si la API Key ya existe para lanzar una excepción Conflict
    const existingKey = await this.apiKeyRepository.findOne({
      where: { nameApiKey: name },
    });

    if (existingKey) {
      throw new ConflictException(`API Key con nombre ${name} ya existe`);
    }

    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });

      const newApiKey = this.apiKeyRepository.create({
        nameApiKey: name,
        privateKey: privateKey,
        enabled: true,
        failedAttempts: 0, // Iniciar con 0 intentos fallidos
      });

      await this.apiKeyRepository.save(newApiKey);
      console.log(`API Key creada: ${name}`);

      return { nameApiKey: newApiKey.nameApiKey, publicKey };
    } catch (error) {
      console.error(`Error al crear la API Key: ${name}`, error);
      throw new InternalServerErrorException('Error al crear la API Key');
    }
  }

  // Método para validar usuario y contraseña
  private async validateUser(
    username: string,
    password: string,
  ): Promise<boolean> {
    // Aquí deberías implementar la lógica para validar el usuario y la contraseña
    // por ejemplo, consultando una base de datos con usuarios registrados.
    // Este es un ejemplo simplificado:
    const validUsername = 'user@example.com';
    const validPassword = 'password123';

    if (username === validUsername && password === validPassword) {
      return true;
    } else {
      throw new UnauthorizedException('Usuario o contraseña incorrectos');
    }
  }

  // Método para generar un JWT y cifrarlo con la clave privada de la API Key
  public async login(
    apiKey: string,
    encryptedUsername: string,
    encryptedPassword: string,
  ): Promise<string> {
    // Primero, desciframos el username y el password
    const username = encryptedUsername;
    const password = encryptedPassword;

    // Luego, validamos las credenciales
    const isValidUser = await this.validateUser(username, password);

    if (isValidUser) {
      const payload = { username };
      const token = this.jwtService.sign(payload);

      // Cifra el JWT con la clave privada de la API Key
      const key = await this.apiKeyRepository.findOne({
        where: { nameApiKey: apiKey, enabled: true },
      });

      if (!key) {
        throw new UnauthorizedException('API Key inválida o deshabilitada');
      }

      const encryptedToken = crypto.privateEncrypt(
        key.privateKey,
        Buffer.from(token),
      );
      return encryptedToken.toString('base64');
    } else {
      throw new UnauthorizedException('Usuario o contraseña incorrectos');
    }
  }
}
