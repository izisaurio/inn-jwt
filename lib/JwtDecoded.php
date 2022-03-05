<?php

namespace Inn;

/**
 * Decoded Jwt
 *
 * @author  izisaurio
 * @version 1
 */
class JwtDecoded
{
	/**
	 * Jwt object
	 *
	 * @access  private
	 * @var     Jwt
	 */
	private $jwt;

	/**
	 * Token received
	 *
	 * @access  private
	 * @var     string
	 */
	private $token;

	/**
	 * Header
	 *
	 * @access  private
	 * @var     string
	 */
	private $headerEncoded;

	/**
	 * Payload
	 *
	 * @access  private
	 * @var     string
	 */
	private $payloadEncoded;

	/**
	 * Signature
	 *
	 * @access  private
	 * @var     string
	 */
	private $signature;

	/**
	 * Decoded header
	 *
	 * @access  public
	 * @var     array
	 */
	public $header;

	/**
	 * Decoded payload
	 *
	 * @access  public
	 * @var     array
	 */
	public $payload;

	/**
	 * Construct
	 *
	 * @access  public
	 * @param   string  $token  Jwt encoded
	 * @param   string  $algo   Algorith used
	 */
	public function __construct($jwt, $token)
	{
		$this->jwt = $jwt;
		$this->token = $token;
		list($header, $payload, $signature) = explode('.', $token);
		$this->headerEncoded = $header;
		$this->payloadEncoded = $payload;
		$this->header = \json_decode(Base64Url::decode($header));
		$this->payload = \json_decode(Base64Url::decode($payload));
		$this->signature = $signature;
	}

	/**
	 * Validate token
	 *
	 * @access  public
	 * @return  bool
	 */
	public function validate()
	{
		if (
			preg_match(
				'/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
				$this->token
			) !== 1
		) {
			return false;
		}
		$signature = hash_hmac(
			$this->jwt->algo[0],
			"{$this->headerEncoded}.{$this->payloadEncoded}",
			$this->jwt->getSecret(),
			true
		);
		if (!\hash_equals(Base64URL::encode($signature), $this->signature)) {
			return false;
		}
		if (isset($this->payload->nbf) && time() <= $this->payload->nbf) {
			return false;
		}
		if (isset($this->payload->exp) && time() >= $this->payload->exp) {
			return false;
		}
		return true;
	}
}
