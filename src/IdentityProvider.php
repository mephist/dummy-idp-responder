<?php

//namespace App\Domain\Saml\Data;

class IdentityProvider {

    private $idp_config;
    private $cert_file;
    private $key_file;

    public function __construct($config)
    {
      $this->config = $config;
      $this->cert_file = $config['idp']['cert'];
      $this->key_file = $config['idp']['key'];
      if (isset($config['sps']) ) {
         $this->trusted_sps = [];
         foreach($config['sps'] as $k => $v) {
           if (is_string($v)) {
              $this->trusted_sps[$k] = $v;
           } elseif (is_array($v)) {
              $this->trusted_sps[$v['entity_id']] = $v['acs_url'];
           }
         }
      }

    }

    // Defining some trusted Service Providers.
    private $trusted_sps = [
      'urn:service:provider:id' => 'https://missing-sp-configuration.idp/login/callback',
    ];

    /**
     * Retrieves the Assertion Consumer Service.
     *
     * @param string
     *   The Service Provider Entity Id
     * @return
     *   The Assertion Consumer Service Url.
     */
    public function getServiceProviderAcs($entityId){

      if (isset($this->trusted_sps[$entityId])) {
        return $this->trusted_sps[$entityId];
      }

      return null;
    }

    /**
     * Returning a dummy IdP identifier.
     *
     * @param bool
     *   The Service Provider Entity Id
     * @return string
     */
    public function getIdPId(){
      return "http://10.26.148.43:8080/idp/sso.php";
    }

//http://10.26.148.43:8080/idp/sso.php?SAMLRequest=pZLLbtswEEV%2FReBefEhyLBOWATdGUQNpa8RuF90UY2kUE5FIhUP19fXRowXSjREgO4I8wzv3zqwJ2qbT2z5c7D0%2B9Ugh%2BtU2lvT0ULDeW%2B2ADGkLLZIOpT5uP97phEvdeRdc6Ro2l1yHgQh9MM6yFwKvLtn%2BO946S32L%2Foj%2Bhynxy%2F1dwS4hdKSFeHyompafva2UTBYLSNMYFlAq5PAE3NjA%2FziLAgazwiM0LQnymRJn7x7Ri7Ehgbbq3ICyaDdkYSyMorPEoKAkT264ynKepTqXuRSm6gSR492lY9F750ucsixYDQ0hi%2Fa7gu1335c3FaxWEmIJ1SrOcokx1HUZ11LVK8jOcrmQA0zU495SABsKlshExTKPVXpSmVaJziRXy%2FQbiw5%2Fg39nbGXsw%2FUUzzNE%2BsPpdIgPn48nFn1FT5OvAWCb9ehcT%2BJ%2B88Yw1%2BLlZ%2Bt5vT4NTe13B9eY8ne0bRr383YoCViw4HuccmshXLcx3pgqridUd6MBCjgMSmxmzf%2B3ePMM&RelayState=PtCJPt8HGLYn7bnIMvJNhaJR3yLCqjv8ou94wn2Cvxc.9dtAfnUiC2A.oss
        
    /**
     * Retrieves the certificate from the IdP in PEM format.
     * @param string
     *   Strip PEM headers
     * @return \LightSaml\Credential\X509Certificate
     */

    public function getCertificatePEM($strip = false) {
        $cert =  file_get_contents($this->cert_file);
        if ($strip) {
          $cert = preg_replace('/^\W+\w+\s+\w+\W+\s(.*)\s+\W+.*$/s', '$1', $cert);
        }
        return $cert;
    }
    
    /**
     * Retrieves the key from the IdP in PEM format.
     * @param string
     *   Strip PEM headers
     * @return \LightSaml\Credential\X509Certificate
     */

    public function getPrivateKeyPEM($strip = false) {
      $cert =  file_get_contents($this->key_file);
      if ($strip) {
        $cert = preg_replace('/^\W+\w+\s+\w+\W+\s(.*)\s+\W+.*$/s', '$1', $cert);
      }
      return $cert;
  }


    /**
     * Retrieves the certificate from the IdP.
     *
     * @return \LightSaml\Credential\X509Certificate
     */
    public function getCertificate(){
        return \LightSaml\Credential\X509Certificate::fromFile($this->cert_file);
    }
  
      /**
       * Retrieves the private key from the Idp.
       *
       * @return \RobRichards\XMLSecLibs\XMLSecurityKey
       */
      public function getPrivateKey(){
        return \LightSaml\Credential\KeyHelper::createPrivateKey($this->key_file, '', true);
      }
  
      /**
       * Returns a user email.
       *
       * @return string
       * @TODO: get from Data Mapping object
       */
      public function getUserEmail(){
  
        return "saml@tester.com";
      }
  
  }

