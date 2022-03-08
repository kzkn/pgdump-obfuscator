package main

type Configuration struct {
	Obfuscations []TargetedObfuscation
}

// TODO: read from file?
var Config *Configuration = &Configuration{
	Obfuscations: []TargetedObfuscation{
		TargetedObfuscation{
			Target{Table: "auth_user", Column: "email"},
			ScrambleEmail,
		},
		TargetedObfuscation{
			Target{Table: "auth_user", Column: "password"},
			ScrambleBytes,
		},

		// address_useraddress
		TargetedObfuscation{
			Target{Table: "address_useraddress", Column: "phone_number"},
			ScrambleDigits,
		},
		TargetedObfuscation{
			Target{Table: "address_useraddress", Column: "land_line"},
			ScrambleDigits,
		},

		// order_order
		TargetedObfuscation{
			Target{Table: "order_order", Column: "guest_email"},
			ScrambleEmail,
		},

		// order_shippingaddress
		TargetedObfuscation{
			Target{Table: "order_shippingaddress", Column: "phone_number"},
			ScrambleDigits,
		},
		TargetedObfuscation{
			Target{Table: "order_shippingaddress", Column: "land_line"},
			ScrambleDigits,
		},
	},
}
