import joi from "joi";

const tokenReqSchema = joi.object().keys({
  token: joi.string().required(),
});

const emailReqSchema = joi.object().keys({
  email: joi.string().required(),
});

const passwordValidation = joi.string().required();

const signInUserSchema = emailReqSchema.keys({
  password: passwordValidation,
});

const signUpUserSchema = signInUserSchema.keys({
  name: joi.string().required(),
});

const resetPassSchema = tokenReqSchema.keys({
  newPass: passwordValidation,
});

export {
  signUpUserSchema,
  signInUserSchema,
  tokenReqSchema,
  emailReqSchema,
  resetPassSchema,
};
