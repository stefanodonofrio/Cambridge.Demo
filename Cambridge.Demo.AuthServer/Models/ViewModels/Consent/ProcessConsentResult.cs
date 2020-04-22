﻿using IdentityServer4.Models;

namespace Cambridge.Demo.AuthServer.Models
{
	public class ProcessConsentResult
	{
		public bool IsRedirect => RedirectUri != null;
		public string RedirectUri { get; set; }
		public Client Client { get; set; }

		public bool ShowView => ViewModel != null;
		
		public ConsentViewModel ViewModel { get; set; }

		public bool HasValidationError => ValidationError != null;
		public string ValidationError { get; set; }
    }
}