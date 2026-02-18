//About: when using validation in your routes,
//ts uses these definitions to autocomplete, warn if using it incorrectly,
//and show what parameters are required

import {Request, Response, NextFunction} from 'express';
import {ValidationChain} from 'express-validator';

declare module './middleware/inputValidation' {
  //Validation error response structure
  interface ValidationError{
    field: string; //which field failed
    message: string; //error message
    value: any; //what value was submitted
  }

 interface ValidationErrorResponse{
    success: false; //false when validation fails
    message: 'Validation failed'; //error message
    requestId: string; //unique request ID for tracking
    timestamp: string; //when it happened
    errors: ValidationError[]; //array of individual errors
  }

  // Common validations object has the listed properties
  interface CommonValidations {
    email: ValidationChain;
    password: ValidationChain;
    userId: ValidationChain;
    string: (field: string, maxLength?: number) => ValidationChain;
    url: (field: string) => ValidationChain;
    integer: (field: string, min?: number, max?: number) => ValidationChain;
    array: (field: string, maxItems?: number) => ValidationChain;
  }
  
 // Validate middleware function signature
 //the validate function takes an array of validators and returns a middleware
 //function
  type ValidateMiddleware = (
    validations: ValidationChain[]
  ) => (req: Request, res: Response, next: NextFunction) => Promise<void>;

  // Exports
  export const validate: ValidateMiddleware;
  export const commonValidations: CommonValidations;
}