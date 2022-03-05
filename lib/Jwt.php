<?php

namespace Inn;

/**
 * Jwt
 *
 * @author  izisaurio
 * @version 1
 */
class Jwt
{
	/**
	 * Token signature secret
	 *
	 * @access  private
	 * @var     string
	 */
	private $secret;

	/**
	 * Issuer
	 *
	 * @access  public
	 * @var     string
	 */
	public $issuer = 'Inn';

	/**
	 * Algo used (first value code, second value name)
	 *
	 * @access  public
	 * @var     array
	 */
	public $algo = ['sha256', 'HS256'];

	/**
	 * Valid not before time
	 *
	 * @access  public
	 * @var     int
	 */
	public $notBefore;

	/**
	 * Token expiries
	 *
	 * @access  public
	 * @var     int
	 */
	public $expires;

	/**
	 * Construct
	 *
	 * Sets the token secret
	 *
	 * @access  public
	 * @param   string  $secret     Jwt signature secret
	 */
	public function __construct($secret)
	{
		$this->secret = $secret;
	}

	/**
	 * Creates the Jwt token
	 *
	 * @access  public
	 * @param   array   $data   Data to store
	 * @return  string
	 */
	public function encode(array $data)
	{
		$header = [
			'type' => 'JWT',
			'alg' => $this->algo[1],
		];
		$payload = [
			'iss' => $this->issuer,
			'iat' => time(),
			'data' => $data,
		];
		if (isset($this->notBefore)) {
			$payload['nbf'] = $this->notBefore;
		}
		if (isset($this->expires)) {
			$payload['exp'] = $this->expires;
		}
		$headerEncoded = Base64Url::encode(\json_encode($header));
		$payloadEncoded = Base64Url::encode(\json_encode($payload));
		$signature = \hash_hmac(
			$this->algo[0],
			"{$headerEncoded}.{$payloadEncoded}",
			$this->secret,
			true
		);
		$signatureEncoded = Base64Url::encode($signature);
		return "{$headerEncoded}.{$payloadEncoded}.{$signatureEncoded}";
	}

	/**
	 * Decodes a token
	 *
	 * @access  pubic
	 * @param   string  $token  Encoded token
	 * @return  JwtDecoded
	 */
	public function decode($token)
	{
		return new JwtDecoded($this, $token);
	}

	/**
	 * Returns the secret
	 *
	 * @access  public
	 * @return  string
	 */
	public function getSecret()
	{
		return $this->secret;
	}
}
