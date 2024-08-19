import { PartialType } from '@nestjs/mapped-types';
import { CreateApiKeyDto } from './create-auth.dto';

export class UpdateAuthDto extends PartialType(CreateApiKeyDto) {}
