// types.ts
import { ValidationError } from 'joi';

interface Validated<T> {
  value: T;
  error?: ValidationError;
}