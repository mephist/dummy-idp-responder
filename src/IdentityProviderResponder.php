<?php

//namespace App\Domain\Saml\Service;

//use App\Domain\Saml\Data\IdentityProvider;
/**
 * Service.
 */
final class IdentityProviderResponder 
{

    private $idp;

    public function __construct(IdentityProvider $idp)
    {
        $this->idp = $idp;
    }

    /**
     * Reads a SAMLRequest from the HTTP request and returns a messageContext.
     *
     * @param \Psr\Http\Message\ServerRequestInterface; $request
     *   The HTTP request.
     *
     * @return \LightSaml\Context\Profile\MessageContext
     *   The MessageContext that contains the SAML message.
     */

    private function readSamlRequest($saml_request)
    {
        $decoded = base64_decode($saml_request);
        $xml = gzinflate($decoded);

        $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
        $deserializationContext->getDocument()->loadXML($xml);

        $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
        $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        return $authnRequest;

    }

    /**
    * Constructs a SAML Response.
    *
    * @param string $saml_request
    *   The SAMLRequest value.
    * @param array $data
    *   Idenity Data
    */

    public function createSamlResponse($saml_request, $data)
    {
        $saml_request = $this->readSamlRequest($saml_request);
        $issuer = $saml_request->getIssuer()->getValue();
        $request_id = $saml_request->getID();

        $user_email = $data['email'];
        $user_id = $user_email;


        //$idp = $this->repository->getIdentityProvider($realm);
        $idp = $this->idp;
        //TODO: check ACS in trusted
        $acsUrl = $idp->getServiceProviderAcs($issuer);

	$attrib = new \LightSaml\Model\Assertion\Attribute();
	$attrib->setName('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name');
	$attrib->setAttributeValue($user_email);

        // Preparing the response XML
        $serializationContext = new \LightSaml\Model\Context\SerializationContext();

        // We now start constructing the SAML Response using LightSAML.
        $response = new \LightSaml\Model\Protocol\Response();
        $response
            ->addAssertion($assertion = new \LightSaml\Model\Assertion\Assertion())
            ->setStatus(new \LightSaml\Model\Protocol\Status(
                new \LightSaml\Model\Protocol\StatusCode(
                    \LightSaml\SamlConstants::STATUS_SUCCESS)
                )
            )
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($acsUrl)
            // We obtain the Entity ID from the Idp.
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($idp->getIdPId()))
        ;

        $assertion
            ->setId(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            // We obtain the Entity ID from the Idp.
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($idp->getIdPId()))
            ->setSubject(
                (new \LightSaml\Model\Assertion\Subject())
                    // Here we set the NameID that identifies the name of the user.
                    ->setNameID(new \LightSaml\Model\Assertion\NameID(
                        $user_id,
                        \LightSaml\SamlConstants::NAME_ID_FORMAT_PERSISTENT
                    ))
                    ->addSubjectConfirmation(
                        (new \LightSaml\Model\Assertion\SubjectConfirmation())
                            ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                    // We set the ResponseTo to be the id of the SAMLRequest.
                                    ->setInResponseTo($request_id)
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    // The recipient is set to the Service Provider ACS.
                                    ->setRecipient($acsUrl)
                            )
                    )
            )
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        // Use the Service Provider Entity ID as AudienceRestriction.
                        new \LightSaml\Model\Assertion\AudienceRestriction([$issuer])
                    )
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute($attrib))
            ->addItem(
                (new \LightSaml\Model\Assertion\AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex($assertion->getId())
                    ->setAuthnContext(
                        (new \LightSaml\Model\Assertion\AuthnContext())
                            ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_UNSPECIFIED)
                    )
            )
        ;

        // Sign the response.
        $response->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($idp->getCertificate(), $idp->getPrivateKey(), "http://www.w3.org/2001/04/xmlenc#sha256"));

        // Serialize to XML.
        $response->serialize($serializationContext->getDocument(), $serializationContext);

        // Set the postback url obtained from the trusted SPs as the destination.
        $response->setDestination($acsUrl);
                    
        //error_log($response);

        return $response;

    }


    public function preparePostBinding($saml_response, $relay_state)
    {
        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($saml_response);
        // Ensure we include the RelayState.
        $message = $messageContext->getMessage();
        $message->setRelayState($relay_state);
        $messageContext->setMessage($message);

        return $postBinding->send($messageContext);
    }

}
