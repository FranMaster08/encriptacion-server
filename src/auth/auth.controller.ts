import {
  Controller,
  Get,
  Post,
  Body,
  BadRequestException,
  Headers,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  CreateApiKeyDto,
  ValidateAndDecryptDto,
  LoginDto,
} from './dto/create-auth.dto';
import { ApiTags, ApiResponse, ApiOperation } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('create-api-key')
  @ApiOperation({ summary: 'Crear una nueva API Key' })
  @ApiResponse({ status: 201, description: 'API Key creada exitosamente' })
  @ApiResponse({
    status: 400,
    description: 'El nombre de la API Key es requerido',
  })
  async createApiKey(@Body() createApiKeyDto: CreateApiKeyDto) {
    if (!createApiKeyDto.name) {
      throw new BadRequestException('El nombre de la API Key es requerido');
    }

    const apiKeyData = await this.authService.createApiKey(
      createApiKeyDto.name,
    );
    return {
      message: 'API Key creada exitosamente',
      nameApiKey: apiKeyData.nameApiKey,
      publicKey: apiKeyData.publicKey,
    };
  }

  @Post('validate-and-decrypt')
  @ApiOperation({ summary: 'Validar y descifrar un mensaje' })
  @ApiResponse({ status: 200, description: 'Mensaje descifrado exitosamente' })
  @ApiResponse({ status: 400, description: 'No se pudo descifrar el mensaje' })
  async validateAndDecrypt(
    @Body() validateAndDecryptDto: ValidateAndDecryptDto,
  ) {
    const { apiKey, encryptedText } = validateAndDecryptDto;

    if (!apiKey || !encryptedText) {
      throw new BadRequestException(
        'API Key y el texto cifrado son requeridos',
      );
    }

    const decryptedText = await this.authService.validarYDescifrar(
      apiKey,
      encryptedText,
    );

    if (!decryptedText) {
      throw new BadRequestException('No se pudo descifrar el mensaje');
    }

    return {
      message: 'Mensaje descifrado exitosamente',
      decryptedText,
    };
  }

  @Get('api-keys')
  @ApiOperation({ summary: 'Listar todas las API Keys' })
  @ApiResponse({ status: 200, description: 'Listado de API Keys' })
  async listApiKeys() {
    const apiKeys = await this.authService.listarApiKeys();
    return apiKeys;
  }

  @Post('login')
  @ApiOperation({ summary: 'Login y generación de JWT' })
  @ApiResponse({
    status: 200,
    description: 'Login exitoso, JWT generado y cifrado',
  })
  @ApiResponse({
    status: 400,
    description: 'API Key, username y password son requeridos',
  })
  async login(
    @Headers('x-api-key') apiKey: string,
    @Body() loginDto: LoginDto,
  ) {
    const { username, password } = loginDto;

    if (!apiKey || !username || !password) {
      throw new BadRequestException(
        'API Key, username y password son requeridos',
      );
    }

    // Primero, desciframos el username y el password
    const decryptedUsername = await this.authService.validarYDescifrar(
      apiKey,
      username,
    );
    const decryptedPassword = await this.authService.validarYDescifrar(
      apiKey,
      password,
    );

    // Luego, validamos las credenciales y generamos el JWT
    const token = await this.authService.login(
      apiKey,
      decryptedUsername,
      decryptedPassword,
    );
    console.log(token);

    return { token };
  }
}
