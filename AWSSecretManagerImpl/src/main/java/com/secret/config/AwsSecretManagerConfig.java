package com.secret.config;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClient;
import com.amazonaws.services.secretsmanager.model.CreateSecretRequest;
import com.amazonaws.services.secretsmanager.model.CreateSecretResult;
import com.amazonaws.services.secretsmanager.model.DeleteSecretRequest;
import com.amazonaws.services.secretsmanager.model.Filter;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.ListSecretsRequest;
import com.amazonaws.services.secretsmanager.model.ListSecretsResult;
import com.amazonaws.services.secretsmanager.model.SecretListEntry;
import com.amazonaws.services.secretsmanager.model.UpdateSecretRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class AwsSecretManagerConfig
{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(AwsSecretManagerConfig.class);

	static AWSSecretsManager client;

	public AwsSecretManagerConfig()
	{
		super();
		client = AWSSecretsManagerClient.builder().build();
	}

	public boolean checkIfSecretKeyExists(final String secretKey)
	{
		return fetchSecrets(client, secretKey).contains(secretKey);
	}

	public String createNewSecret(final String secretKey, final String secretValue, final String secretDesc) throws Exception
	{
		if (!checkIfSecretKeyExists(secretKey))
		{
			try
			{
				final CreateSecretRequest createSecretRequest = new CreateSecretRequest().withName(secretKey);
				final JSONObject secretValues = new JSONObject();
				secretValues.put(secretKey, secretValue);

				createSecretRequest.setDescription(secretDesc);
				createSecretRequest.setSecretString(secretValues.toString());

				LOGGER.debug("Creating a secret " + secretKey);

				final CreateSecretResult secretResponse = client.createSecret(createSecretRequest);

				if (secretResponse.getARN().length() > 0)
					return getValueFromSecretManager(secretKey);
			}
			catch (final Exception e)
			{
				throw new Exception("Got error while creating a secret in aws SecretManager " + e
					.getMessage());
			}
		}

		return updateSecret(secretKey, secretValue, secretDesc);
	}

	public void deleteSecret(final String secretKey) throws Exception
	{

		try
		{
			final DeleteSecretRequest deleteSecretRequest = new DeleteSecretRequest().withSecretId(secretKey);

			deleteSecretRequest.setForceDeleteWithoutRecovery(true);

			LOGGER.debug("Deleting a secret " + secretKey);

			client.deleteSecret(deleteSecretRequest);
		}
		catch (final Exception e)
		{
			throw new Exception("Got error while deleting secret from aws SecretManager " + e.getMessage());
		}

	}

	public final Set<String> fetchSecrets(final AWSSecretsManager client, final String key)
	{
		final Set<SecretListEntry> secrets = new HashSet<>();
		String nextToken = null;
		do
		{
			final Filter filters = new Filter();
			filters.withKey("name");
			filters.withValues(key);

			final ListSecretsRequest request = new ListSecretsRequest().withFilters(filters);

			if (nextToken != null)
			{
				request.setNextToken(nextToken);
			}

			final ListSecretsResult result = client.listSecrets(request);
			secrets.addAll(result.getSecretList());

			nextToken = result.getNextToken();
		}
		while (nextToken != null && nextToken.length() != 0);

		final Set<String> secretNames = new HashSet<>();

		secrets.forEach(n -> secretNames.add(n.getName()));

		return secretNames;
	}
	

	public String getValueFromSecretManager(final String secretKey) throws Exception
	{

		final ObjectMapper objectMapper = new ObjectMapper();

		JsonNode secretsJson = null;

		try
		{

			final GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretKey);

			GetSecretValueResult getSecretValueResponse;

			getSecretValueResponse = client.getSecretValue(getSecretValueRequest);

			final String secret = getSecretValueResponse.getSecretString();

			if (secret != null)
			{
				try
				{
					secretsJson = objectMapper.readTree(secret);
				}

				catch (final IOException e)
				{
					LOGGER.error("Exception while retrieving secret values: " + e.getMessage());
				}

				return secretsJson.get(secretKey).textValue();
			}

		}
		catch (final Exception e)
		{
			throw new Exception("Got error while fetching secret value from aws SecretManager " + e
				.getMessage());
		}

		return null;
	}

	public String updateSecret(final String secretKey, final String secretValue, final String secretDesc) throws Exception
	{
		try
		{
			final UpdateSecretRequest updateSecretRequest = new UpdateSecretRequest().withSecretId(secretKey);

			final JSONObject secretValues = new JSONObject();
			secretValues.put(secretKey, secretValue);

			updateSecretRequest.setDescription(secretDesc);
			updateSecretRequest.setSecretString(secretValues.toString());

			client.updateSecret(updateSecretRequest);

			return getValueFromSecretManager(secretKey);
		}
		catch (final Exception e)
		{
			throw new Exception("Got error while updating secret value to aws SecretManager " + e
				.getMessage());
		}
	}

}
