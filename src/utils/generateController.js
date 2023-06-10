export const generateController = (handler) => {
  const requestHandler = async (request, response) => {
    let isException = false;

    const raiseException = (status, message, payload) => {
      isException = true;
      response.status(status).json({
        message,
        ...(payload ? { payload } : {}),
        success: false,
      });

      return {
        message,
        ...(payload ? { payload } : {}),
      };
    };

    try {
      const handlerResponse = await handler(request, response, raiseException);

      if (!isException && handlerResponse) {
        return response.status(200).json({
          message: handlerResponse.message,
          ...(handlerResponse.payload
            ? { payload: handlerResponse.payload }
            : {}),
          success: true,
        });
      }
    } catch (e) {
      let message = "message";

      e?.response?.data && e?.response?.data?.errors?.length
        ? e?.response?.data?.errors?.forEach(
            (item) => (message += ` ${item.detailMessage}`)
          )
        : (message = e.message);
      response.status(500).json({
        message: message,
        success: false,
      });
    }
  };
  return requestHandler;
};
