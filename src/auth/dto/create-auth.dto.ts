import { ApiProperty } from '@nestjs/swagger';

export class CreateApiKeyDto {
  @ApiProperty({
    description: 'Nombre de la API Key',
    example: 'thv-front-core',
  })
  name: string;
}

export class ValidateAndDecryptDto {
  @ApiProperty({
    description: 'API Key utilizada para el descifrado',
    example: 'thv-front-core',
  })
  apiKey: string;

  @ApiProperty({
    description: 'Texto cifrado en base64',
    example: 'k9V9OMqN9+GUz43KqWGqCjiksek5SuvI7/u3HlRiBgP4khE8pmDA...',
  })
  encryptedText: string;
}

export class LoginDto {
  @ApiProperty({
    description: 'Username cifrado en base64',
    example: 'k9V9OMqN9+GUz43KqWGqCjiksek5SuvI7/u3HlRiBgP4khE8pmDA...',
  })
  username: string;

  @ApiProperty({
    description: 'Password cifrado en base64',
    example: 'aW5jb3JyZWN0U2VjcmV0UGFzc3dvcmQ=',
  })
  password: string;
}
